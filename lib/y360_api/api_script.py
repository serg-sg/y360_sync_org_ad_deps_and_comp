import requests
import csv
import json
import os
import secrets
import string
import random
from typing import List, Dict, Union, Any, Tuple, Optional

from dotenv import load_dotenv
from pprint import pprint

import asyncio
import aiohttp
from aiohttp import client_exceptions


# --- Настройка констант по умолчанию ---
# Если эти константы уже определены в другом месте кода (например, в конфиге), они не будут перезаписаны.
# Это позволяет гибко настраивать скрипт извне.

if 'API_RATE_LIMIT_SEMAPHORE' not in globals():
    API_RATE_LIMIT_SEMAPHORE = 20  # Максимальное кол-во параллельных запросов (Rate Limit)

if 'REQUEST_TIMEOUT_SECONDS' not in globals():
    REQUEST_TIMEOUT_SECONDS = 30   # Таймаут выполнения одного HTTP-запроса в секундах

# -------------------------------------


class API360:
    def __init__(self, org_id, access_token):
        self.url = f"https://api360.yandex.net/directory/v1/org/{org_id}"
        self.url_rules = f"https://api360.yandex.net/admin/v1/mail/routing/org/{org_id}/rules"
        self.url_disk = f"https://api360.yandex.net/admin/v1/disk/resources/public?orgId={org_id}"
        self.headers = {
            "Authorization": f"OAuth {access_token}"
        }
        self.org_id = org_id

        self.per_page = 100
        self.temp_password = "00ff00ff00"

    async def _make_api_request_async(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        semaphore: Optional[asyncio.Semaphore] = None,
        json_data: Optional[Union[Dict[str, Any], List[Any]]] = None,
        params: Optional[Dict[str, Any]] = None,
        operation_name: str = "API request",
        retry_on_500: bool = True,
        max_retries: int = 1,
        retry_delay: float = 1.0,
        jitter: bool = True,
        log_success: bool = False,  # По умолчанию успехи не логируем (слишком шумно)
    ) -> Dict[str, Any]:
        """
        Универсальный метод для выполнения HTTP-запросов к API Яндекс 360.
        Инкапсулирует всю повторяющуюся логику: jitter, семафор, retry, обработку ошибок.

        :param session: Активная aiohttp.ClientSession.
        :param method: HTTP-метод (GET, POST, PATCH, PUT, DELETE).
        :param url: Полный URL запроса.
        :param semaphore: Семафор для контроля конкурентности.
        :param json_data: Тело запроса (будет отправлено как JSON).
        :param params: Query-параметры URL.
        :param operation_name: Человекочитаемое имя операции (для логов).
        :param retry_on_500: Выполнять ли повторную попытку при 500 Internal Server Error.
        :param max_retries: Максимальное количество повторных попыток.
        :param retry_delay: Базовая задержка перед retry (в секундах).

        :return: Стандартизированный словарь:
            {
                'status_code': int | None,   # HTTP-код ответа (None при сетевой ошибке)
                'success': bool,             # True только если status 2xx
                'data': dict | None,         # Распарсенный JSON (если удалось распарсить)
                'error': str | None,         # Человекочитаемое описание ошибки
                'error_type': str | None,    # Классификатор: 'http_4xx', 'http_5xx',
                                             #   'timeout', 'network', 'json_decode',
                                             #   'retry_exhausted', 'unexpected'
                'retried': bool,             # Был ли выполнен retry
                'raw_text': str | None       # Сырой текст ответа (для диагностики, до 500 символов)
            }
        """
        # Инициализация стандартизированного результата
        result = {
            'status_code': None,
            'success': False,
            'data': None,
            'error': None,
            'error_type': None,
            'retried': False,
            'raw_text': None,
            'url': url,           # Сохраняем для диагностики
            'method': method,
        }

        method = method.upper()

        # Короткий префикс для логов — чтобы легко grep-ать
        tag = f"[API] [{operation_name}]"

        async def _execute_one() -> Dict[str, Any]:
            res = dict(result)
            try:
                async with session.request(
                    method, url, json=json_data, params=params
                ) as resp:
                    res['status_code'] = resp.status

                    # Читаем сырой текст (первые 500 символов — для диагностики)
                    try:
                        raw = await resp.text()
                        res['raw_text'] = raw[:500] if raw else None
                    except Exception as e:
                        res['raw_text'] = f"<не удалось прочитать тело: {e}>"

                    # === 2xx: Успех ===
                    if 200 <= resp.status < 300:
                        try:
                            res['data'] = await resp.json(content_type=None)
                        except (aiohttp.ContentTypeError, ValueError, json.JSONDecodeError):
                            res['data'] = {}
                        res['success'] = True
                        if log_success:
                            print(f"{tag} ✓ {method} {resp.status}")
                        return res

                    # === Ошибки: логируем ПОЛНЫЙ ответ API ===
                    if 500 <= resp.status < 600:
                        res['error_type'] = 'http_5xx'
                        res['error'] = self._extract_api_error_message(res['raw_text'], 'серверная ошибка')
                        print(f"{tag} ✗ HTTP {resp.status} (5xx): {res['error']}")
                        print(f"{tag}   raw: {res['raw_text']}")
                        return res

                    if resp.status == 429:
                        res['error_type'] = 'rate_limited'
                        res['error'] = "Превышен лимит запросов (HTTP 429)"
                        print(f"{tag} ✗ HTTP 429 Rate Limited")
                        return res

                    if resp.status in (401, 403):
                        res['error_type'] = 'auth'
                        res['error'] = self._extract_api_error_message(
                            res['raw_text'], f"HTTP {resp.status}: нет прав доступа"
                        )
                        print(f"{tag} ✗ HTTP {resp.status} Auth: {res['error']}")
                        return res

                    if resp.status == 404:
                        res['error_type'] = 'not_found'
                        res['error'] = self._extract_api_error_message(res['raw_text'], "Ресурс не найден")
                        # 404 — ожидаемая ситуация, логируем кратко
                        print(f"{tag} ✗ HTTP 404: {res['error']}")
                        return res

                    if 400 <= resp.status < 500:
                        res['error_type'] = 'http_4xx'
                        res['error'] = self._extract_api_error_message(
                            res['raw_text'], f"HTTP {resp.status}: некорректный запрос"
                        )
                        print(f"{tag} ✗ HTTP {resp.status}: {res['error']}")
                        # Для 4xx особенно важно видеть детали — там часто валидация
                        if res['raw_text']:
                            print(f"{tag}   raw: {res['raw_text']}")
                        return res

                    res['error_type'] = 'unexpected_status'
                    res['error'] = f"Неожиданный HTTP-статус: {resp.status}"
                    print(f"{tag} ✗ {res['error']}")
                    return res

            except asyncio.TimeoutError:
                res['error_type'] = 'timeout'
                res['error'] = f"Тайм-аут соединения при {method}"
                print(f"{tag} ✗ TIMEOUT: {res['error']}")
                return res
            except aiohttp.ClientError as e:
                res['error_type'] = 'network'
                res['error'] = f"Сетевая ошибка: {type(e).__name__}: {e}"
                print(f"{tag} ✗ NETWORK: {res['error']}")
                return res
            except Exception as e:
                res['error_type'] = 'unexpected'
                res['error'] = f"Неожиданная ошибка: {type(e).__name__}: {e}"
                import traceback
                print(f"{tag} ✗ UNEXPECTED: {res['error']}")
                print(traceback.format_exc())  # Полный traceback только для неожиданных ошибок
                return res

        # --- Семафор, jitter, retry ---
        async def _run_with_semaphore():
            if jitter:
                await asyncio.sleep(random.uniform(0.01, 0.05))

            response = await _execute_one()

            if retry_on_500 and response.get('error_type') == 'http_5xx' and max_retries > 0:
                for attempt in range(1, max_retries + 1):
                    response['retried'] = True
                    sleep_time = retry_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.3)
                    print(f"{tag} ↻ RETRY {attempt}/{max_retries} через {sleep_time:.2f}s")
                    await asyncio.sleep(sleep_time)
                    response = await _execute_one()

                    if response['success']:
                        print(f"{tag} ✓ Успех после retry #{attempt}")
                        break
                    if response.get('error_type') != 'http_5xx':
                        break
                else:
                    if response.get('error_type') == 'http_5xx':
                        response['error_type'] = 'retry_exhausted'
                        response['error'] = f"HTTP 5xx после {max_retries} повторных попыток"
                        print(f"{tag} ✗ RETRY EXHAUSTED: {response['error']}")

            return response

        if semaphore is not None:
            async with semaphore:
                return await _run_with_semaphore()
        return await _run_with_semaphore()

    @staticmethod
    def _extract_api_error_message(raw_text: Optional[str], default: str) -> str:
        """
        Извлекает человекочитаемое сообщение об ошибке из JSON-ответа API.
        Если парсинг не удался — возвращает default + первые 200 символов текста.
        """
        if not raw_text:
            return default
        try:
            err_data = json.loads(raw_text)
            msg = err_data.get('message') or err_data.get('error') or default
            details = err_data.get('details')
            if details:
                msg += f" | details: {str(details)[:200]}"
            return msg
        except (ValueError, AttributeError, TypeError):
            return f"{default} | raw: {raw_text[:200]}"

    # Подразделения
    def check_connections_for_deps(self) -> bool:
        """
        Проверка доступности API подразделений (health-check).
        Возвращает True при успешном соединении и валидном ответе API, иначе False.
        Используется для предварительной проверки конфигурации, токена и сети.

        :return: bool — результат проверки соединения
        """
        url = f"{self.url}/departments"
        
        # Health-check должен быть быстрым: 10 секунд достаточно
        timeout = aiohttp.ClientTimeout(total=10)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                # Используем универсальную функцию для единой обработки ошибок
                response = await self._make_api_request_async(
                    session=session,
                    method="GET",
                    url=url,
                    params={'page': 1, 'perPage': 1},  # Минимум данных для проверки связи
                    operation_name="check_deps_connection",
                    retry_on_500=False,  # Health-check должен отражать текущее состояние
                    max_retries=0,
                    jitter=False,
                    semaphore=None,
                )
                return response['success']

        try:
            return asyncio.run(run_async())
        except RuntimeError as e:
            # Защита от вызова внутри уже активного event loop
            print(f"[CHECK-DEPS] ✗ RuntimeError: {e}")
            return False
        except Exception as e:
            print(f"[CHECK-DEPS] ✗ Неожиданная ошибка: {type(e).__name__}: {e}")
            return False

    # Получение всех подразделений организации
    async def _get_departments_async_page(
        self,
        session: aiohttp.ClientSession,
        page: int,
        per_page: int,
        semaphore: asyncio.Semaphore
    ) -> dict:
        """
        Внутренний метод для асинхронного получения одной страницы подразделений.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param page: Номер страницы для загрузки
        :param per_page: Количество подразделений на странице
        :param semaphore: Семафор для ограничения параллельности (передаётся извне)
        :return: Словарь с данными страницы (departments, page, pages, total) или {} при ошибке
        """
        url = f"{self.url}/departments"
        op_name = f"get_departments_page({page})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            params={'page': page, 'perPage': per_page},
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=False,
        )

        # Контракт возврата: словарь страницы или {} при ошибке.
        # Это важно для совместимости с get_departments_list_async,
        # который делает first_page.get('departments', []).
        if response['success'] and isinstance(response['data'], dict):
            return response['data']
        return {}

    async def get_departments_list_async(self) -> list:
        """
        Асинхронное ПАРАЛЛЕЛЬНОЕ получение всех подразделений организации.
        Определяет общее количество страниц по первому запросу, а остальные скачивает одновременно.

        :return: Список словарей с данными подразделений
        """
        PER_PAGE = 100  # Максимальный разумный размер страницы
        all_departments = []
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

        async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
            # Загружаем первую страницу для получения метаданных
            first_page = await self._get_departments_async_page(session, 1, PER_PAGE, semaphore)

            departments = first_page.get('departments', [])
            if not departments:
                return []

            all_departments.extend(departments)
            total_pages = first_page.get('pages', 1) or 1  # Защита от None

            # Если страниц больше одной, запускаем сбор остальных параллельно
            if total_pages > 1:
                tasks = [
                    self._get_departments_async_page(session, p, PER_PAGE, semaphore)
                    for p in range(2, total_pages + 1)
                ]
                pages_results = await asyncio.gather(*tasks, return_exceptions=True)

                for data in pages_results:
                    if isinstance(data, dict):
                        all_departments.extend(data.get('departments', []))
                    elif isinstance(data, Exception):
                        print(f"Исключение задачи во время параллельной загрузки: {data}")

        return all_departments

    def get_departments_list(self) -> list:
        """
        Чтение всех подразделений предприятия.
        Синхронная обёртка над get_departments_list_async для обратной совместимости.

        :return: Список словарей с данными подразделений

        Примеры:
            # Прямой вызов
            departments = organization.get_departments_list()
            print(f"Загружено подразделений: {len(departments)}")
        """
        return asyncio.run(self.get_departments_list_async())

    # Подразделения
    # Посмотреть информацию о подразделении по ID
    async def _get_department_info_by_id_async(
        self,
        session: aiohttp.ClientSession,
        department_id: int
    ) -> Optional[Dict[str, Any]]:
        """
        Асинхронное получение информации об одном подразделении по ID.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param department_id: Идентификатор подразделения
        :return: Словарь с данными подразделения или None при ошибке/отсутствии
        """
        url = f"{self.url}/departments/{department_id}"
        op_name = f"get_department({department_id})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,
        )

        if response['success']:
            return response['data']

        # При ошибке возвращаем None — это контракт оригинального метода.
        # Подробная ошибка уже залогирована в _make_api_request_async.
        return None

    def get_department_info_by_id(self, department_id: int) -> Optional[Dict[str, Any]]:
        """
        Посмотреть информацию о подразделении по ID.
        Синхронная обёртка над _get_department_info_by_id_async.

        :param department_id: Идентификатор подразделения
        :return: Словарь с информацией о подразделении или None при ошибке
        """
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                return await self._get_department_info_by_id_async(session, department_id)

        return asyncio.run(run_async())

    # Подразделения
    # Поиск ID подразделения по названию и родительскому ID
    def get_department_id_by_name(
        self,
        department_name: str,
        parent_id: int = 1
    ) -> Optional[int]:
        """
        Поиск ID подразделения по названию и родительскому ID.

        :param department_name: Точное название подразделения
        :param parent_id: ID родительского подразделения (по умолчанию 1 — корень)
        :return: ID подразделения (int) или None, если не найдено / ошибка загрузки
        """
        if not department_name:
            print("[DEP-SEARCH] ✗ department_name не может быть пустым")
            return None

        # Получаем список подразделений (после рефакторинга — параллельно и с retry)
        try:
            all_deps = self.get_departments_list()
        except Exception as e:
            print(f"[DEP-SEARCH] ✗ Ошибка загрузки списка подразделений: {type(e).__name__}: {e}")
            return None

        if not all_deps:
            print(f"[DEP-SEARCH] ✗ Список подразделений пуст (искомое: '{department_name}', parentId={parent_id})")
            return None

        # Линейный поиск по точному совпадению имени и родителя
        for dep in all_deps:
            if dep.get("name") == department_name and dep.get("parentId") == parent_id:
                dep_id = dep.get("id")
                print(f"[DEP-SEARCH] ✓ Найдено: '{department_name}' (parentId={parent_id}) → ID={dep_id}")
                return dep_id

        # Не найдено — логируем для диагностики
        print(
            f"[DEP-SEARCH] ✗ Подразделение не найдено: name='{department_name}', parentId={parent_id}. "
            f"Всего подразделений в списке: {len(all_deps)}"
        )
        return None

    def get_department_id_by_name_cached(
        self,
        department_name: str,
        parent_id: int = 1,
        _cache: dict = None
    ) -> Optional[int]:
        """Версия с кэшированием списка подразделений для массовых вызовов."""
        if _cache is None:
            # При первом вызове загружаем и индексируем
            all_deps = self.get_departments_list() or []
            _cache = {
                (d.get("name"), d.get("parentId")): d.get("id")
                for d in all_deps
            }
        
        key = (department_name, parent_id)
        result = _cache.get(key)
        if result is None:
            print(f"[DEP-SEARCH] ✗ Не найдено в кэше: name='{department_name}', parentId={parent_id}")
        return result

    # Подразделения
    # Получает подразделение по его externalId
    def get_department_info_by_external_id(self, external_id: str) -> Dict[str, Any]:
        """
        Получает подразделение по его externalId.
        
        :param external_id: Внешний идентификатор подразделения (externalId).
        :return: Словарь с результатом:
                 - Успех: {'success': True, 'id': <int>, 'name': <str>, ...}
                 - Не найдено: {'success': False, 'error': 'Department not found'}
                 - Дубликаты: {'success': False, 'error': 'Multiple departments found', 'duplicates': [...]}
                 - Ошибка получения списка: {'success': False, 'error': <str>}

        Примеры:
            result = organization.get_department_id_by_external_id("DEP-IT-001")

            if result['success']:
                print(f"Подразделение найдено: ID={result['id']}, Name={result['name']}")
                print(f"Родитель: {result['parentId']}, Сотрудников: {result['membersCount']}")
            else:
                print(f"Ошибка: {result['error']}")
                if 'duplicates' in result:
                    for dup in result['duplicates']:
                        print(f"  Дубликат: ID={dup['id']}, Name={dup['name']}, ParentID={dup['parentId']}")
        """
        tag = "[DEP-SEARCH-BY-EXTID]"

        # --- Валидация входных данных ---
        if not external_id:
            print(f"{tag} ✗ externalId не может быть пустым")
            return {'success': False, 'error': 'externalId не может быть пустым'}

        # --- Загрузка списка подразделений ---
        try:
            departments = self.get_departments_list()
        except Exception as e:
            err_msg = f"Ошибка при получении списка подразделений: {type(e).__name__}: {e}"
            print(f"{tag} ✗ {err_msg}")
            return {'success': False, 'error': err_msg}

        if not departments:
            print(f"{tag} ✗ Список подразделений пуст (искомый externalId='{external_id}')")
            return {'success': False, 'error': 'Список подразделений пуст или не получен'}

        # --- Поиск по externalId ---
        matched = [dep for dep in departments if dep.get('externalId') == external_id]

        # Не найдено
        if len(matched) == 0:
            print(
                f"{tag} ✗ Подразделение не найдено: externalId='{external_id}'. "
                f"Всего подразделений: {len(departments)}"
            )
            return {
                'success': False,
                'error': f'Подразделение с externalId="{external_id}" не найдено',
            }

        # Дубликаты
        if len(matched) > 1:
            duplicates_info = [
                {
                    'id': dep.get('id'),
                    'name': dep.get('name'),
                    'externalId': dep.get('externalId'),
                    'parentId': dep.get('parentId'),
                }
                for dep in matched
            ]
            print(
                f"{tag} ✗ Найдено {len(matched)} подразделений с одинаковым "
                f"externalId='{external_id}': {[d['id'] for d in duplicates_info]}"
            )
            return {
                'success': False,
                'error': (
                    f'Найдено несколько подразделений ({len(matched)}) '
                    f'с одинаковым externalId="{external_id}"'
                ),
                'duplicates': duplicates_info,
            }

        # --- Успех: возвращаем полные данные подразделения ---
        department = matched[0]
        print(
            f"{tag} ✓ Найдено: externalId='{external_id}' → "
            f"ID={department.get('id')}, name='{department.get('name')}'"
        )
        return {
            'success': True,
            **department,  # Все поля подразделения (id, name, parentId, description, externalId, email, membersCount, ...)
        }

    # Подразделения
    # Удаление подразделений
    async def _delete_department_by_id_async(
        self,
        session: aiohttp.ClientSession,
        department_id: int,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Dict[str, Any]:
        """
        Асинхронное удаление подразделения по ID.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param department_id: Идентификатор подразделения
        :param semaphore: Опциональный семафор для ограничения параллельности
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/departments/{department_id}"
        op_name = f"delete_department({department_id})"

        response = await self._make_api_request_async(
            session=session,
            method="DELETE",
            url=url,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        # --- Шаблон ответа ---
        result = {
            "department_id": department_id,
            "success": False,
            "error": None,
            "response_data": None,
        }

        # Успех: проверяем поле removed (согласно документации API подразделений)
        if response["success"]:
            data = response["data"] or {}
            removed = data.get("removed", False) if isinstance(data, dict) else False
            if not removed:
                result["error"] = "Подразделение не удалено (removed=false)"
                result["response_data"] = data
                return result
            result["success"] = True
            result["response_data"] = data
            return result

        # Ошибки: передаём сообщение из универсальной функции
        result["error"] = response["error"]
        result["response_data"] = response["raw_text"]
        return result

    def delete_department_by_id(self, dep_id: int) -> Dict[str, Any]:
        """
        Удаление подразделения по ID.
        Синхронная обёртка над _delete_department_by_id_async.

        :param dep_id: Идентификатор подразделения
        :return: Словарь с результатом: {department_id, success, error, response_data}
        """
        if not dep_id:
            return {
                "department_id": dep_id,
                "success": False,
                "error": "department_id не может быть пустым или равным 0",
                "response_data": None,
            }

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                return await self._delete_department_by_id_async(session, dep_id)

        return asyncio.run(run_async())

    def post_create_department_alias(self):
        pass

    def delete_department_alias(self):
        pass

    # Подразделения
    # Обновление информации о подразделении
    async def _patch_department_info_async(
        self,
        session: aiohttp.ClientSession,
        department_id: int,
        data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Асинхронное обновление информации о подразделении.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param department_id: Идентификатор подразделения
        :param data: Словарь с полями для обновления (name, parentId, description, externalId, label)
        :return: Словарь с обновлёнными данными подразделения или None при ошибке
        """
        url = f"{self.url}/departments/{department_id}"
        op_name = f"patch_department({department_id})"

        response = await self._make_api_request_async(
            session=session,
            method="PATCH",
            url=url,
            json_data=data,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,
        )

        if response['success']:
            return response['data'] if isinstance(response['data'], dict) else {}

        # При ошибке возвращаем None — контракт оригинального метода.
        # Подробная ошибка уже залогирована в _make_api_request_async.
        return None

    def patch_department_info(
        self,
        department_id: int,
        data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Изменяет информацию о подразделении.
        Изменяются значения только тех параметров, которые были переданы в запросе.
        Синхронная обёртка над _patch_department_info_async.

        :param department_id: Идентификатор подразделения
        :param data: Словарь с полями для обновления. Возможные поля:
                    - name (str): Название подразделения
                    - parentId (int): Идентификатор родительского подразделения
                    - description (str): Описание подразделения
                    - externalId (str): Произвольный внешний идентификатор
                    - label (str): Имя почтовой рассылки подразделения
        :return: Словарь с обновленной информацией о подразделении или None при ошибке

        Примеры:
            result = organization.patch_department_info(
                department_id=123,
                data={"name": "Новое название", "externalId": "AD-DEP-001"}
            )
            if result:
                print(result['name'])
        """
        # --- Валидация входных данных (ранний выход без сети) ---
        if not department_id:
            print("[DEP-PATCH] ✗ department_id не может быть пустым или равным 0")
            return None

        if not data:
            print("[DEP-PATCH] ✗ data не может быть пустым")
            return None

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                return await self._patch_department_info_async(session, department_id, data)

        result = asyncio.run(run_async())

        if result is not None:
            print(f"[DEP-PATCH] ✓ Подразделение ID:{department_id} успешно обновлено")
        # Ошибка уже залогирована в _make_api_request_async с префиксом [API] [patch_department(N)]

        return result

    # Подразделения
    # Создание подразделения
    async def _post_create_department_async(
        self,
        session: aiohttp.ClientSession,
        department_info: dict,
    ) -> Dict[str, Any]:
        """
        Асинхронное создание подразделения.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param department_info: Словарь с данными подразделения (name, parentId, description, externalId, label)
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/departments"
        dep_name = department_info.get('name', '(без имени)')
        op_name = f"create_department({dep_name})"

        response = await self._make_api_request_async(
            session=session,
            method="POST",
            url=url,
            json_data=department_info,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,
        )

        # --- Маппинг под контракт вызывающего кода ---
        if response['success']:
            return {
                'success': True,
                'message': f"Department {dep_name} was created successfully",
                'data': response['data'] if isinstance(response['data'], dict) else {},
            }

        return {
            'success': False,
            'message': f"During creating Department {dep_name} occurred error: {response['error']}",
            'data': None,
            'raw_text': response['raw_text'],
        }

    def post_create_department(self, department_info: dict) -> Tuple[bool, str]:
        """
        Создание подразделения.
        Синхронная обёртка над _post_create_department_async.

        :param department_info: Словарь с данными подразделения. Обязательные поля: name, parentId.
                                Опциональные: description, externalId, label.
        :return: Кортеж (успех: bool, сообщение: str) — для обратной совместимости.

        Примеры:
            success, message = organization.post_create_department({
                "name": "Новый отдел",
                "parentId": 1,
                "externalId": "AD-DEP-NEW-001"
            })
            if success:
                print(message)
            else:
                print(f"Ошибка: {message}")
        """
        if not department_info or not isinstance(department_info, dict):
            return False, "department_info должен быть непустым словарём"

        if not department_info.get('name'):
            return False, "Поле 'name' обязательно для создания подразделения"

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                return await self._post_create_department_async(session, department_info)

        result = asyncio.run(run_async())
        return result['success'], result['message']


    # Группы
    # Получение всех групп организации
    async def _get_groups_async_page(
        self,
        session: aiohttp.ClientSession,
        page: int,
        per_page: int,
        semaphore: asyncio.Semaphore
    ) -> dict:
        """
        Внутренний метод для асинхронного получения одной страницы групп.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param page: Номер страницы для загрузки
        :param per_page: Количество групп на странице
        :param semaphore: Семафор для ограничения параллельности (передаётся извне)
        :return: Словарь с данными страницы (groups, page, pages, total) или {} при ошибке
        """
        url = f"{self.url}/groups"
        op_name = f"get_groups_page({page})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            params={'page': page, 'perPage': per_page},
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=False,
        )

        # Контракт возврата: словарь страницы или {} при ошибке.
        # Это важно для совместимости с get_groups_list_async,
        # который делает first_page.get('groups', []).
        if response['success'] and isinstance(response['data'], dict):
            return response['data']
        return {}

    async def get_groups_list_async(self) -> list:
        """
        Асинхронное ПАРАЛЛЕЛЬНОЕ получение всех групп организации.
        Определяет общее количество страниц по первому запросу, а остальные скачивает одновременно.

        :return: Список словарей с данными групп
        """
        PER_PAGE = 100  # Максимальный разумный размер страницы
        all_groups = []
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

        async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
            # Загружаем первую страницу для получения метаданных
            first_page = await self._get_groups_async_page(session, 1, PER_PAGE, semaphore)

            groups = first_page.get('groups', [])
            if not groups:
                return []

            all_groups.extend(groups)
            total_pages = first_page.get('pages', 1) or 1  # Защита от None

            # Если страниц больше одной, запускаем сбор остальных параллельно
            if total_pages > 1:
                tasks = [
                    self._get_groups_async_page(session, p, PER_PAGE, semaphore)
                    for p in range(2, total_pages + 1)
                ]
                pages_results = await asyncio.gather(*tasks, return_exceptions=True)

                for data in pages_results:
                    if isinstance(data, dict):
                        all_groups.extend(data.get('groups', []))
                    elif isinstance(data, Exception):
                        print(f"Исключение задачи во время параллельной загрузки групп: {data}")

        return all_groups

    def get_groups_list(self) -> list:
        """
        Чтение всех групп предприятия.
        Синхронная обёртка над get_groups_list_async для обратной совместимости.

        :return: Список словарей с данными групп
        """
        return asyncio.run(self.get_groups_list_async())

    # Группы
    # Получает группу по её externalId
    def get_group_info_by_external_id(self, external_id: str) -> Dict[str, Any]:
        """
        Получает группу по её externalId.
        Использует get_groups_list() (параллельная загрузка с retry).

        :param external_id: Внешний идентификатор группы.
        :return: Словарь с результатом:
                - Успех: {'success': True, ...полные данные группы...}
                - Не найдено: {'success': False, 'error': '...'}
                - Дубликаты: {'success': False, 'error': '...', 'duplicates': [...]}
                - Ошибка: {'success': False, 'error': '...'}
        """
        tag = "[GRP-SEARCH-BY-EXTID]"

        # --- Валидация входных данных ---
        if not external_id:
            print(f"{tag} ✗ externalId не может быть пустым")
            return {'success': False, 'error': 'externalId не может быть пустым'}

        # --- Загрузка списка групп ---
        try:
            groups = self.get_groups_list()
        except Exception as e:
            err_msg = f"Ошибка при получении списка групп: {type(e).__name__}: {e}"
            print(f"{tag} ✗ {err_msg}")
            return {'success': False, 'error': err_msg}

        if not groups:
            print(f"{tag} ✗ Список групп пуст (искомый externalId='{external_id}')")
            return {'success': False, 'error': 'Список групп пуст или не получен'}

        # --- Поиск по externalId ---
        matched = [g for g in groups if g.get('externalId') == external_id]

        # Не найдено
        if len(matched) == 0:
            print(
                f"{tag} ✗ Группа не найдена: externalId='{external_id}'. "
                f"Всего групп: {len(groups)}"
            )
            return {
                'success': False,
                'error': f'Группа с externalId="{external_id}" не найдена',
            }

        # Дубликаты
        if len(matched) > 1:
            duplicates_info = [
                {
                    'id': g.get('id'),
                    'name': g.get('name'),
                    'externalId': g.get('externalId'),
                }
                for g in matched
            ]
            print(
                f"{tag} ✗ Найдено {len(matched)} групп с одинаковым "
                f"externalId='{external_id}': {[d['id'] for d in duplicates_info]}"
            )
            return {
                'success': False,
                'error': (
                    f'Найдено несколько групп ({len(matched)}) '
                    f'с одинаковым externalId="{external_id}"'
                ),
                'duplicates': duplicates_info,
            }

        # --- Успех: возвращаем полные данные группы ---
        group = matched[0]
        print(
            f"{tag} ✓ Найдено: externalId='{external_id}' → "
            f"ID={group.get('id')}, name='{group.get('name')}'"
        )
        return {
            'success': True,
            **group,  # Все поля группы из API (id, name, type, description, membersCount, label, email, externalId, ...)
        }

    # Группы
    # Просмотреть параметры группы по ID
    def get_group_info_by_id(self, group_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """
        Просмотреть параметры группы по ID.
        Синхронный метод, использующий асинхронное ядро _make_api_request_async
        для единой обработки HTTP-ошибок, retry и логирования.

        :param group_id: Идентификатор группы
        :return: Словарь с информацией о группе или None при ошибке/отсутствии
        """
        if not group_id:
            print("[GRP-GET] ✗ group_id не может быть пустым")
            return None

        # Внутренняя асинхронная функция для запуска через asyncio.run
        async def fetch_group() -> Optional[Dict[str, Any]]:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                # Единая точка обработки HTTP-ошибок, retry, логирования
                response = await self._make_api_request_async(
                    session=session,
                    method="GET",
                    url=f"{self.url}/groups/{group_id}",
                    operation_name=f"get_group({group_id})",
                    retry_on_500=True,
                    max_retries=1,
                    retry_delay=1.0,
                    jitter=False,  # Для одиночного запроса jitter не нужен
                    semaphore=None, # Семафор не нужен
                    log_success=False, # Не логируем успех (слишком шумно для одиночного запроса)
                )

                # Возвращаем данные при успехе, иначе None
                return response['data'] if response['success'] else None

        # Запускаем асинхронную логику синхронно
        try:
            return asyncio.run(fetch_group())
        except RuntimeError as e:
            # Например, если get_group_info_by_id вызывается внутри другого async-контекста
            print(f"[GRP-GET] ✗ RuntimeError при вызове asyncio.run: {e}")
            return None

    # Группы
    # Создание группы
    async def _post_create_group_async(
        self,
        session: aiohttp.ClientSession,
        group_info: dict,
    ) -> Dict[str, Any]:
        """
        Асинхронное создание группы.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param group_info: Словарь с данными группы (name, type, description, externalId, label, email)
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/groups"
        group_name = group_info.get('name', '(без имени)')
        op_name = f"create_group({group_name})"

        response = await self._make_api_request_async(
            session=session,
            method="POST",
            url=url,
            json_data=group_info,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,
        )

        # --- Маппинг под ожидаемый результат ---
        if response['success']:
            return {
                'success': True,
                'message': f"Group {group_name} was created successfully",
                'data': response['data'] if isinstance(response['data'], dict) else {},
            }

        return {
            'success': False,
            'message': f"During creating Group {group_name} occurred error: {response['error']}",
            'data': None,
            'raw_text': response['raw_text'],
        }

    def post_create_group(self, group_info: dict) -> Dict[str, Any]:
        """
        Создание группы.
        Синхронная обёртка над _post_create_group_async.

        :param group_info: Словарь с данными группы. Обязательные поля: name.
                        Опциональные: type, description, externalId, label, email.
        :return: Словарь с результатом: {'success': bool, 'message': str, 'data': dict или None}
        """
        if not group_info or not isinstance(group_info, dict):
            message = "group_info должен быть непустым словарём"
            print(f"[GRP-CREATE] ✗ {message}")
            return {'success': False, 'message': message, 'data': None}

        if not group_info.get('name'):
            message = "Поле 'name' обязательно для создания группы"
            print(f"[GRP-CREATE] ✗ {message}")
            return {'success': False, 'message': message, 'data': None}

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                return await self._post_create_group_async(session, group_info)

        result = asyncio.run(run_async())

        # Логируем результат
        if result['success']:
            print(f"[GRP-CREATE] ✓ {result['message']}")
        else:
            print(f"[GRP-CREATE] ✗ {result['message']}")

        return result

    # Группы
    # Изменяет информацию о группе
    async def _patch_group_info_async(
        self,
        session: aiohttp.ClientSession,
        group_id: Union[str, int],
        data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Асинхронное обновление информации о группе.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param group_id: Идентификатор группы
        :param data: Словарь с полями для обновления (name, description, externalId, label, email)
        :return: Словарь с обновлёнными данными группы или None при ошибке
        """
        url = f"{self.url}/groups/{group_id}"
        op_name = f"patch_group({group_id})"

        response = await self._make_api_request_async(
            session=session,
            method="PATCH",
            url=url,
            json_data=data,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,
        )

        if response['success']:
            return response['data'] if isinstance(response['data'], dict) else {}

        # При ошибке возвращаем None — текущий контракт метода.
        # Подробная ошибка уже залогирована в _make_api_request_async.
        return None

    def patch_group_info(
        self,
        group_id: Union[str, int],
        data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Изменяет информацию о группе.
        Изменяются значения только тех параметров, которые были переданы в запросе.
        Синхронная обёртка над _patch_group_info_async.

        :param group_id: Идентификатор группы
        :param data: Словарь с полями для обновления. Возможные поля:
                    - name (str): Название группы
                    - description (str): Описание группы
                    - externalId (str): Произвольный внешний идентификатор
                    - label (str): Имя почтовой рассылки группы
                    - email (str): Адрес электронной почты группы
        :return: Словарь с обновленной информацией о группе или None при ошибке
        """
        # --- Валидация входных данных (ранний выход без сети) ---
        if not group_id:
            print("[GRP-PATCH] ✗ group_id не может быть пустым")
            return None

        if not data:
            print("[GRP-PATCH] ✗ data не может быть пустым")
            return None

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                return await self._patch_group_info_async(session, group_id, data)

        result = asyncio.run(run_async())

        if result is not None:
            print(f"[GRP-PATCH] ✓ Группа ID:{group_id} успешно обновлена")
        # Ошибка уже залогирована в _make_api_request_async с префиксом [API] [patch_group(N)]

        return result

    # Группы
    # Удаление группы по ID
    async def _delete_group_by_id_async(
        self,
        session: aiohttp.ClientSession,
        group_id: Union[str, int],
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Dict[str, Any]:
        """
        Асинхронное удаление группы по ID.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.
        Проверяет поле 'removed' в ответе согласно документации API.

        :param session: Активный aiohttp.ClientSession
        :param group_id: Идентификатор группы
        :param semaphore: Опциональный семафор для ограничения параллельности
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/groups/{group_id}"
        op_name = f"delete_group({group_id})"

        response = await self._make_api_request_async(
            session=session,
            method="DELETE",
            url=url,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        # --- Шаблон ответа ---
        result = {
            "group_id": group_id,
            "success": False,
            "error": None,
            "response_data": None,
        }

        # Успех: проверяем поле removed (согласно документации API групп)
        if response["success"]:
            data = response["data"] or {}
            removed = data.get("removed", False) if isinstance(data, dict) else False
            if not removed:
                result["error"] = "Группа не удалена (removed=false)"
                result["response_data"] = data
                return result
            result["success"] = True
            result["response_data"] = data
            return result

        # Ошибки: передаём сообщение из универсальной функции
        result["error"] = response["error"]
        result["response_data"] = response["raw_text"]
        return result

    def delete_group_by_id(self, group_id: Union[str, int]) -> Dict[str, Any]:
        """
        Удаление группы по ID.
        Синхронная обёртка над _delete_group_by_id_async.

        :param group_id: Идентификатор группы
        :return: Словарь с результатом: {group_id, success, error, response_data}
        """
        if not group_id:
            return {
                "group_id": group_id,
                "success": False,
                "error": "group_id не может быть пустым",
                "response_data": None,
            }

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                return await self._delete_group_by_id_async(session, group_id)

        return asyncio.run(run_async())

    # Группы
    # Получение всех участников указанной групп
    async def _get_group_members_page_async(
        self,
        session: aiohttp.ClientSession,
        group_id: Union[str, int],
        page: int,
        per_page: int,
        semaphore: asyncio.Semaphore
    ) -> dict:
        """
        Внутренний метод для асинхронного получения одной страницы участников группы.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param group_id: Идентификатор группы
        :param page: Номер страницы для загрузки
        :param per_page: Количество участников на странице
        :param semaphore: Семафор для ограничения параллельности (передаётся извне)
        :return: Словарь с данными страницы (users, page, pages, total) или {} при ошибке
        """
        url = f"{self.url}/groups/{group_id}/members"
        op_name = f"get_group_members_page({group_id}, p{page})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            params={'page': page, 'perPage': per_page},
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=False,  # jitter не нужен для пагинации внутри одной сессии
        )

        # Контракт возврата: словарь страницы или {} при ошибке.
        # Это важно для совместимости с get_group_members_list_async,
        # который делает first_page.get('users', []).
        if response['success'] and isinstance(response['data'], dict):
            return response['data']
        return {}

    async def get_group_members_list_async(self, group_id: Union[str, int]) -> list:
        """
        Асинхронное ПАРАЛЛЕЛЬНОЕ получение всех участников указанной группы.
        Определяет общее количество страниц по первому запросу, а остальные скачивает одновременно.

        :param group_id: Идентификатор группы
        :return: Список словарей с данными участников (типы: user, group, department)
        """
        PER_PAGE = 100  # Максимальный разумный размер страницы
        all_members = []
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

        async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
            # Загружаем первую страницу для получения метаданных
            first_page = await self._get_group_members_page_async(session, group_id, 1, PER_PAGE, semaphore)

            members = first_page.get('users', []) # API возвращает "users" для участников
            if not members:
                # Даже если страница есть, но участников нет, возвращаем пустой список
                # Если first_page пустой или ошибка, members = [] тоже
                return []

            all_members.extend(members)
            total_pages = first_page.get('pages', 1) or 1  # Защита от None

            # Если страниц больше одной, запускаем сбор остальных параллельно
            if total_pages > 1:
                tasks = [
                    self._get_group_members_page_async(session, group_id, p, PER_PAGE, semaphore)
                    for p in range(2, total_pages + 1)
                ]
                pages_results = await asyncio.gather(*tasks, return_exceptions=True)

                for data in pages_results:
                    if isinstance(data, dict):
                        all_members.extend(data.get('users', [])) # Снова "users"
                    elif isinstance(data, Exception):
                        print(f"Исключение задачи во время параллельной загрузки участников группы {group_id}: {data}")

        return all_members

    def get_group_members_by_id(self, group_id: Union[str, int]) -> Optional[list]:
        """
        Просмотреть список участников группы.
        Синхронная обёртка над get_group_members_list_async.
        ВАЖНО: Возвращает список *всех* участников группы (через пагинацию), а не только первую страницу.

        :param group_id: Идентификатор группы
        :return: Список словарей с участниками группы ([{'type': 'user', 'id': '...'}, ...])
                или None при ошибке получения первой страницы.
                Если участников нет, возвращает [].

        Примеры:
            members_list = organization.get_group_members_by_id("group_id_1")
            if members_list is not None:
                print(f"Найдено {len(members_list)} участников.")
                for member in members_list:
                    print(f"- {member['type']}: {member['id']}")
            else:
                print("Не удалось получить список участников.")
        """
        if not group_id:
            print("[GRP-MEMBERS] ✗ group_id не может быть пустым")
            return None

        try:
            all_members = asyncio.run(self.get_group_members_list_async(group_id))

            if all_members is None:
                print(f"[GRP-MEMBERS] ✗ Не удалось получить список участников для группы {group_id}. Подробности в логе API.")
                return None

            print(f"[GRP-MEMBERS] ✓ Получено {len(all_members)} участников для группы {group_id}.")
            return all_members

        except RuntimeError as e:
            print(f"[GRP-MEMBERS] ✗ RuntimeError при вызове asyncio.run: {e}")
            return None

    # Группы
    # Добавление участника(ов) в группу(ы)
    async def _add_member_to_group_async(
        self,
        session: aiohttp.ClientSession,
        group_id: Union[str, int],
        member_type: str, # "user", "group", "department"
        member_id: Union[str, int],
        semaphore: asyncio.Semaphore
    ) -> Dict[str, Any]:
        """
        Асинхронное добавление одного участника в группу.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param group_id: Идентификатор группы, в которую добавляется участник
        :param member_type: Тип участника ("user", "group", "department")
        :param member_id: Идентификатор участника (пользователя, группы или подразделения)
        :param semaphore: Семафор для ограничения параллельности
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/groups/{group_id}/members"
        op_name = f"add_member_to_group({group_id}, {member_type}:{member_id})"

        # Формируем тело запроса в соответствии с API документацией.
        # Один участник за вызов.
        payload = {
            "type": member_type,
            "id": str(member_id) # API ожидает строку
        }

        response = await self._make_api_request_async(
            session=session,
            method="POST",
            url=url,
            json_data=payload,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True, # Jitter для рассинхронизации при пакетной обработке
        )

        # --- Шаблон результата ---
        result = {
            "group_id": str(group_id),
            "member_type": member_type,
            "member_id": str(member_id),
            "status": "failed", # Статус по умолчанию
            "message": None,
            "details": None,
        }

        # --- Успех ---
        if response['success']:
            # API возвращает, например, {"id": "12345", "type": "user", "added": true} при успехе добавления
            api_response_data = response['data']
            # Проверим, был ли участник действительно добавлен, если поле 'added' есть
            added_ok = api_response_data.get('added') if isinstance(api_response_data, dict) else True # Если поля нет, считаем, что OK
            if added_ok:
                result["status"] = "success"
                result["message"] = f"Участник {member_type}:{member_id} успешно добавлен в группу {group_id}"
            else:
                result["status"] = "not_added_by_api" # API вернул 200, но added=false
                result["message"] = f"API сообщил, что участник {member_type}:{member_id} не был добавлен в группу {group_id} (added=false)"
            result["details"] = api_response_data if api_response_data else {}
            return result

        # --- Ошибка ---
        # Используем сообщение и тип ошибки, подготовленные _make_api_request_async
        result["message"] = f"Ошибка при добавлении участника: {response['error']}"
        # Опционально: маппинг универсальных error_type в наши бизнес-специфичные статусы
        type_mapping = {
            "not_found": "not_found", # Группа или участник не найден
            "auth": "forbidden",      # 401/403
            "http_4xx": "bad_request", # 400 и другие 4xx (например, уже в группе)
            "retry_exhausted": "server_error", # 5xx после retry
            "timeout": "timeout",
            "network": "network_error",
        }
        result["status"] = type_mapping.get(response['error_type'], "failed")

        # Возвращаем результат с ошибкой, но с контекстом (group_id, member_type, member_id)
        return result

    async def _add_members_to_group_batch_async(
        self,
        session: aiohttp.ClientSession,
        group_id: Union[str, int],
        members_list: List[Dict[str, Union[str, int]]] # [{"type": "...", "id": "..."}, ...]
    ) -> List[Dict[str, Any]]:
        """
        Асинхронное пакетное добавление нескольких участников в одну группу.
        Создаёт задачи для каждого участника и собирает результаты.
        Каждый участник добавляется отдельным вызовом API.

        :param session: Активный aiohttp.ClientSession
        :param group_id: Идентификатор группы
        :param members_list: Список словарей с типом и ID участников
        :return: Список результатов для каждого участника
        """
        semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

        async def bounded_add(member):
            return await self._add_member_to_group_async(
                session, group_id, member["type"], member["id"], semaphore
            )

        tasks = [bounded_add(m) for m in members_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                # Обработка исключения, которое могло произойти внутри задачи asyncio
                member = members_list[i]
                processed_results.append({
                    "group_id": str(group_id),
                    "member_type": member["type"],
                    "member_id": str(member["id"]),
                    "status": "error",
                    "message": f"Исключение задачи asyncio: {type(res).__name__}: {res}",
                    "details": None,
                })
            else:
                processed_results.append(res)

        return processed_results

    def post_add_member_to_group(
        self,
        group_id: Union[str, int],
        members: Union[
            Dict[str, Union[str, int]],           # Один участник: {"type": "...", "id": "..."}
            List[Dict[str, Union[str, int]]]      # Несколько участников в одну группу: [{"type": "...", "id": "..."}, ...]
        ]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Добавление участника(ов) в группу(ы).
        Синхронная обёртка над асинхронными методами.

        :param group_id: Идентификатор группы (для случая с одним или несколькими участниками в одну группу).
                        Если members - список, то все участники добавляются в эту группу.
        :param members: Один участник (словарь) или список участников (список словарей).
                        Каждый словарь должен содержать "type" и "id".
        :return: Словарь результата (если один участник) или список словарей (если несколько участников в одну группу).

        Примеры:
            # 1. Добавить одного участника
            result = organization.post_add_member_to_group(
                group_id=101,
                members={"type": "user", "id": 12345}
            )
            print(result)
            # Пример вывода:
            # [ADD-MEMBER-TO-GROUP] success: Участник user:12345 успешно добавлен в группу 101
            # {'group_id': '101', 'member_type': 'user', 'member_id': '12345', 'status': 'success', 'message': '...', 'details': {...}}


            # 2. Добавить несколько участников в одну группу
            members_to_add = [
                {"type": "user", "id": 67890},
                {"type": "group", "id": 202},
                {"type": "department", "id": 303}
            ]
            results = organization.post_add_member_to_group(
                group_id=101,
                members=members_to_add
            )
            print(results)
            # Пример вывода:
            # [ADD-MEMBER-TO-GROUP] Пакетное добавление в группу 101: Успешно 3/3
            #   - success: Участник user:67890 успешно добавлен в группу 101
            #   - success: Участник group:202 успешно добавлен в группу 101
            #   - success: Участник department:303 успешно добавлен в группу 101
            # [
            #   {'group_id': '101', 'member_type': 'user', 'member_id': '67890', 'status': 'success', ...},
            #   {'group_id': '101', 'member_type': 'group', 'member_id': '202', 'status': 'success', ...},
            #   {'group_id': '101', 'member_type': 'department', 'member_id': '303', 'status': 'success', ...}
            # ]


            # 3. Ошибка валидации
            result = organization.post_add_member_to_group(
                group_id=101,
                members={"type": "invalid_type", "id": 123}
            )
            # Вывод в stdout:
            # [ADD-MEMBER-TO-GROUP] Ошибка: неверный тип участника 'invalid_type'. Допустимо: user, group, department.
            # [ADD-MEMBER-TO-GROUP] validation_error: Нет валидных данных для добавления
            # Возврат:
            # {'group_id': '101', 'member_type': 'invalid_type', 'member_id': '123', 'status': 'validation_error', 'message': 'Нет валидных данных для добавления', 'details': None}
        """
        # Определяем режим: один участник или список
        is_single = isinstance(members, dict)
        members_to_process = [members] if is_single else members

        # Валидация входных данных
        validated_members = []
        for i, member in enumerate(members_to_process):
            if not isinstance(member, dict):
                print(f"[ADD-MEMBER-TO-GROUP] Ошибка: участники должны быть словарями. Элемент {i}: {type(member).__name__}")
                continue
            m_type = member.get("type")
            m_id = member.get("id")
            if not m_type or not m_id:
                print(f"[ADD-MEMBER-TO-GROUP] Ошибка: у участника {i} отсутствует 'type' или 'id'.")
                continue
            # Проверим тип участника
            if m_type not in ["user", "group", "department"]:
                print(f"[ADD-MEMBER-TO-GROUP] Ошибка: неверный тип участника '{m_type}'. Допустимо: user, group, department.")
                continue
            validated_members.append({"type": m_type, "id": m_id})

        if not validated_members:
            print(f"[ADD-MEMBER-TO-GROUP] Нет валидных участников для добавления в группу {group_id}.")
            # Возвращаем заглушку в зависимости от режима
            if is_single:
                return {
                    "group_id": str(group_id),
                    "member_type": getattr(members, 'get', lambda x, d: d)("type", "unknown"),
                    "member_id": str(getattr(members, 'get', lambda x, d: d)("id", "unknown")),
                    "status": "validation_error",
                    "message": "Нет валидных данных для добавления",
                    "details": None,
                }
            else:
                return [] # или список ошибок?

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                if is_single:
                    # Для одного участника используем semaphore в single-методе
                    semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)
                    return await self._add_member_to_group_async(
                        session, group_id, validated_members[0]["type"], validated_members[0]["id"], semaphore
                    )
                else:
                    # Для списка участников используем batch-метод
                    return await self._add_members_to_group_batch_async(session, group_id, validated_members)

        results = asyncio.run(run_async())

        # В случае одиночного добавления результат - один словарь
        if is_single:
            print(f"[ADD-MEMBER-TO-GROUP] {results['status']}: {results['message']}")
            return results

        # В случае пакетного добавления результат - список словарей
        success_count = sum(1 for r in results if r['status'] == 'success')
        total_count = len(results)
        print(f"[ADD-MEMBER-TO-GROUP] Пакетное добавление в группу {group_id}: Успешно {success_count}/{total_count}")

        for r in results:
            print(f"  - {r['status']}: {r['message']}")

        return results

    # Пользователи
    # Получение всех пользователей организации
    async def _get_users_async_page(
        self,
        session: aiohttp.ClientSession,
        page: int,
        per_page: int,
        semaphore: asyncio.Semaphore
    ) -> dict:
        """
        Внутренний метод для асинхронного получения одной страницы пользователей.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param page: Номер страницы для загрузки
        :param per_page: Количество пользователей на странице
        :param semaphore: Семафор для ограничения параллельности (передаётся извне)
        :return: Словарь с данными страницы (users, page, pages, total) или {} при ошибке
        """
        url = f"{self.url}/users"
        op_name = f"get_users_page({page})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            params={'page': page, 'perPage': per_page},
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=False,  # jitter не нужен для пагинации внутри одной сессии
        )

        # Контракт возврата: словарь страницы или {} при ошибке.
        # Это важно для совместимости с get_all_users_async,
        # который делает first_page.get('users', []).
        if response['success'] and isinstance(response['data'], dict):
            return response['data']
        return {}

    async def get_all_users_async(self) -> list:
        """
        Асинхронное ПАРАЛЛЕЛЬНОЕ получение всех пользователей организации.
        Определяет общее количество страниц по первому запросу, а остальные скачивает одновременно.

        :return: Список словарей с данными пользователей
        """
        PER_PAGE = 100  # Увеличиваем размер страницы для эффективности
        all_users = []
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

        async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
            # Загружаем первую страницу для получения метаданных
            first_page = await self._get_users_async_page(session, 1, PER_PAGE, semaphore)

            users = first_page.get('users', [])
            if not users:
                # Даже если страница есть, но пользователей нет, возвращаем пустой список
                # Если first_page пустой или ошибка, users = [] тоже
                return []

            all_users.extend(users)
            total_pages = first_page.get('pages', 1) or 1  # Защита от None

            # Если страниц больше одной, запускаем сбор остальных параллельно
            if total_pages > 1:
                tasks = [
                    self._get_users_async_page(session, p, PER_PAGE, semaphore)
                    for p in range(2, total_pages + 1)
                ]
                pages_results = await asyncio.gather(*tasks, return_exceptions=True)

                for data in pages_results:
                    if isinstance(data, dict):
                        all_users.extend(data.get('users', []))
                    elif isinstance(data, Exception):
                        print(f"Исключение задачи во время параллельной загрузки пользователей: {data}")
                        # В случае ошибки на одной из страниц, мы всё равно возвращаем собранные данные с других.
                        # Это поведение аналогично get_groups_list_async и get_departments_list_async.

        return all_users

    def get_all_users(self, file=False) -> list:
        """
        Получить всех пользователей организации.
        Синхронная обёртка над get_all_users_async.
        Использует параллельную асинхронную загрузку для повышения эффективности.

        :param file: Флаг для сохранения результата в файл (не изменяется).
        :return: Список словарей с данными пользователей.
        """
        # Запускаем асинхронную логику
        try:
            all_users = asyncio.run(self.get_all_users_async())
            # Контракт: возвращаем список пользователей
            # Если get_all_users_async возвращает [] (нет пользователей) или результат с данными - это нормально.
            # Если ошибка получения первой страницы, get_all_users_async вернёт [], и лог уже будет в _make_api_request_async

            # Сохранение в файл (логика без изменений)
            if file:
                API360.save_file("users_output", all_users)

            return all_users

        except RuntimeError as e:
            # Например, если вызывается внутри другого async-контекста
            print(f"[GET-USERS] ✗ RuntimeError при вызове asyncio.run: {e}")
            return [] # Возвращаем пустой список при критической ошибке запуска

    # Пользователи
    # Получить идентификаторы всех пользователей в организации
    def get_all_users_id(self, file=False):
        """
        Получить идентификаторы всех пользователей в организации
        :return: Список идентификаторов пользователей
        """
        users = self.get_all_users()
        ids = []
        for user in users:
            ids.append(user['id'])

        # Получите все идентификаторы пользователей и записать их в файл:
        if file:
            API360.save_file("users_ids_output", ids)

        return ids

    # Пользователи
    # Получить информацию о пользователях по списку ID
    async def _get_user_info_by_id_async(
        self,
        session: aiohttp.ClientSession,
        user_id: Union[str, int],
        semaphore: asyncio.Semaphore
    ) -> Dict[str, Any]:
        """
        Асинхронное получение информации об одном пользователе по ID.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param user_id: Идентификатор пользователя
        :param semaphore: Семафор для ограничения параллельности
        :return: Словарь с результатом операции (информация о пользователе или ошибка)
        """
        url = f"{self.url}/users/{user_id}"
        op_name = f"get_user_info({user_id})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            semaphore=semaphore, # Применяем семафор здесь
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True, # Jitter для рассинхронизации при параллельных вызовах
        )

        # --- Шаблон результата ---
        result = {
            "id": str(user_id),
            "success": False,
            "data": None,
            "error": None,
        }

        # --- Успех ---
        if response['success']:
            result["success"] = True
            result["data"] = response['data'] if isinstance(response['data'], dict) else {}
            return result

        # --- Ошибка ---
        # Используем сообщение и тип ошибки, подготовленные _make_api_request_async
        result["error"] = f"Ошибка при получении информации о пользователе {user_id}: {response['error']}"
        # Возвращаем результат с ошибкой, но с контекстом (user_id)
        return result

    async def _get_users_info_batch_async(
        self,
        session: aiohttp.ClientSession,
        user_ids_list: List[Union[str, int]]
    ) -> List[Dict[str, Any]]:
        """
        Асинхронное пакетное получение информации о пользователях по списку ID.
        Использует семафор для ограничения параллельности и gather для эффективности.

        :param session: Активная сессия aiohttp
        :param user_ids_list: Список ID пользователей
        :return: Список результатов для каждого ID
        """
        semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

        async def bounded_get_info(user_id):
            return await self._get_user_info_by_id_async(session, user_id, semaphore)

        tasks = [bounded_get_info(uid) for uid in user_ids_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                # Обработка исключения, которое могло произойти внутри задачи asyncio
                user_id = user_ids_list[i]
                processed_results.append({
                    "id": str(user_id),
                    "success": False,
                    "data": None,
                    "error": f"Исключение задачи asyncio: {type(res).__name__}: {res}",
                })
            else:
                processed_results.append(res)

        return processed_results

    def get_all_users_info_by_id(self, ids_lst: List[Union[str, int]], file=False, min_info=False):
        """
        Получить информацию о пользователях по списку ID.
        Синхронная обёртка над асинхронными методами.
        Использует параллельную асинхронную загрузку для повышения эффективности.

        :param ids_lst: Список ID пользователей.
        :param file: Флаг для сохранения результата в файл (не изменяется).
        :param min_info: Флаг для возврата минимальной информации о пользователе (не изменяется).
        :return: Кортеж (users_info, user_false), где:
                - users_info: список словарей с информацией о пользователях.
                - user_false: список ID пользователей, информацию о которых не удалось получить.
        """
        if not ids_lst:
            return [], []

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                return await self._get_users_info_batch_async(session, ids_lst)

        results = asyncio.run(run_async())

        # Разделяем результаты на успешные и неудачные
        users_info = []
        user_false = []
        for res in results:
            if res['success']:
                users_info.append(res['data'])
            else:
                user_false.append(res['id'])
                # Логируем ошибку для диагностики
                print(f"[GET-USERS-INFO-BY-ID] {res['error']}")

        # Обработка флага min_info (вместе с file, как в оригинале)
        if file and min_info:
            # Если включены оба флага, создаём упрощённый и агрегированный список
            users_minimized = []
            for user in users_info:
                user_tmp = {}
                try:
                    # Обязательные поля, которые должны быть у каждого пользователя
                    user_tmp['id'] = user.get('id')
                    user_tmp['nickname'] = user.get('nickname')
                    user_tmp['email'] = user.get('email')

                    # Форматирование ФИО в одну строку, как в оригинале
                    # Проверяем наличие самого объекта 'name'
                    name_obj = user.get('name', {}) # Если 'name' нет, используем пустой словарь
                    if isinstance(name_obj, dict): # Убедимся, что 'name' — это словарь
                        # Берём значения. Если ключа нет или он None, используем пустую строку.
                        # Пробел как дефолт не обязателен, если мы всё равно делаем strip() в конце,
                        # но он защищает от TypeError, если вдруг попадётся None вместо строки.
                        last_name = name_obj.get('last') or ' '
                        first_name = name_obj.get('first') or ' '
                        middle_name = name_obj.get('middle') or ' '
                        
                        # Собираем имя и убираем лишние пробелы по краям и между компонентами
                        full_name = ' '.join(part for part in [last_name, first_name, middle_name] if part).strip()
                        
                        # Если после склейки осталось пусто (все части были пустыми), можно оставить пустым или поставить заглушку
                        user_tmp['name'] = full_name
                    else:
                        # Если 'name' не словарь (например, строка или None), задаём стандартное имя
                        user_tmp['name'] = '' # Или можно задать 'Unknown Name'

                    # Дата создания
                    user_tmp['createdAt'] = user.get('createdAt')
                    
                    users_minimized.append(user_tmp)
                except KeyError as e: # Теоретически, .get() не вызывает KeyError, но на всякий случай
                    # Хотя, при текущей логике с .get(), сюда код не должен попасть из-за отсутствия полей в 'name'
                    # Исключение может произойти по другой причине, например, если user не словарь.
                    print(f'!!!!!!!!!!!!!!Unexpected KeyError processing user for min_info: {e}, User ID: {user.get("id", "unknown")}')
                    # Пропускаем пользователя с ошибкой, не добавляем в список
                    continue # Переходим к следующему пользователю
            
            # Перед сохранением в файл используем упрощённый список
            API360.save_file("user_output", users_minimized)
        elif file:
            # Если только file, без min_info, сохраняем оригинальный список
            API360.save_file("users_info_output", users_info)
        # Если только min_info, без file, то просто возвращаем упрощённый список в users_info
        elif min_info:
            users_minimized = []
            for user in users_info:
                user_tmp = {}
                try:
                    user_tmp['id'] = user.get('id')
                    user_tmp['nickname'] = user.get('nickname')
                    user_tmp['email'] = user.get('email')
                    name_obj = user.get('name', {})
                    if isinstance(name_obj, dict): # Убедимся, что 'name' — это словарь
                        # Берём значения. Если ключа нет или он None, используем пустую строку.
                        # Пробел как дефолт не обязателен, если мы всё равно делаем strip() в конце,
                        # но он защищает от TypeError, если вдруг попадётся None вместо строки.
                        last_name = name_obj.get('last') or ' '
                        first_name = name_obj.get('first') or ' '
                        middle_name = name_obj.get('middle') or ' '
                        
                        # Собираем имя и убираем лишние пробелы по краям и между компонентами
                        full_name = ' '.join(part for part in [last_name, first_name, middle_name] if part).strip()
                        
                        # Если после склейки осталось пусто (все части были пустыми), можно оставить пустым или поставить заглушку
                        user_tmp['name'] = full_name
                    else:
                        user_tmp['name'] = ''
                    user_tmp['createdAt'] = user.get('createdAt')
                    
                    users_minimized.append(user_tmp)
                except KeyError as e:
                    print(f'!!!!!!!!!!!!!!Key error for "user": {e}')
                    continue
            users_info = users_minimized

        # Возврат результата
        return users_info, user_false

    # Пользователи
    # Создание пользователя(ей)
    async def _post_create_user_async(
        self,
        session: aiohttp.ClientSession,
        user_info: dict,
        semaphore: asyncio.Semaphore
    ) -> Dict[str, Any]:
        """
        Асинхронное создание одного пользователя.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param user_info: Словарь с данными пользователя
        :param semaphore: Семафор для ограничения параллельности
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/users"
        nickname = user_info.get('nickname', '(без логина)')
        op_name = f"create_user({nickname})"

        response = await self._make_api_request_async(
            session=session,
            method="POST",
            url=url,
            json_data=user_info,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        # --- Шаблон результата ---
        result = {
            "nickname": nickname,
            "success": False,
            "message": None,
            "data": None,
        }

        if response['success']:
            result["success"] = True
            result["message"] = f"Пользователь {nickname} успешно создан"
            result["data"] = response['data'] if isinstance(response['data'], dict) else {}
            return result

        # Ошибки: передаём сообщение из универсальной функции
        result["message"] = f"При создании пользователя {nickname} произошла ошибка: {response['error']}"
        return result

    def post_create_users(self, users_info: Union[Dict[str, Any], List[Dict[str, Any]]]):
        """
        Создание пользователя(ей).
        Поддерживает одного пользователя (dict) или список пользователей (List[dict]).
        Использует асинхронное ядро для единой обработки ошибок и параллелизма.

        :param users_info: Словарь с данными одного пользователя или список словарей.

        Примеры:
            # Один пользователь
            organization.post_create_users({
                "nickname": "test.user",
                "name": {"first": "Тест", "last": "Пользователь"},
                "password": "TempPass123!",
                "departmentId": 1
            })
            # [API] [create_user(test.user)] ✓ POST 200
            # [CREATE-USERS] ✓ User test.user was created successfully

            # Список пользователей
            organization.post_create_users([
                {"nickname": "user1", "name": {"first": "A", "last": "B"}, "password": "Pass1!"},
                {"nickname": "user2", "name": {"first": "C", "last": "D"}, "password": "Pass2!"},
            ])
            # [CREATE-USERS] ■ Итог: успешно=2/2

            # Ошибка (дубликат)
            organization.post_create_users({"nickname": "test.user", ...})
            # [API] [create_user(test.user)] ✗ HTTP 400: ...
            # [CREATE-USERS] ✗ During creating user test.user occurred error: HTTP 400: ...
        """
        # Определяем режим: один пользователь или список
        is_single = isinstance(users_info, dict)
        users_to_process = [users_info] if is_single else users_info

        if not users_to_process:
            print("[CREATE-USERS] ✗ Список пользователей пуст")
            return

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                tasks = [
                    self._post_create_user_async(session, user, semaphore)
                    for user in users_to_process
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                processed_results = []
                for i, res in enumerate(results):
                    if isinstance(res, Exception):
                        nickname = users_to_process[i].get('nickname', f'index_{i}')
                        processed_results.append({
                            "nickname": nickname,
                            "success": False,
                            "message": f"Исключение задачи asyncio: {type(res).__name__}: {res}",
                            "data": None,
                        })
                    else:
                        processed_results.append(res)
                return processed_results

        results = asyncio.run(run_async())

        # Вывод результатов
        success_count = sum(1 for r in results if r['success'])
        total_count = len(results)

        if is_single:
            # Для одного пользователя выводим детальное сообщение
            res = results[0]
            if res['success']:
                print(f"[CREATE-USERS] ✓ {res['message']}")
            else:
                print(f"[CREATE-USERS] ✗ {res['message']}")
        else:
            # Для списка выводим сводку + детали по ошибкам
            print(f"[CREATE-USERS] ■ Итог: успешно={success_count}/{total_count}")
            for r in results:
                if not r['success']:
                    print(f"  ✗ {r['message']}")

    # Пользователи
    # Удаление пользователя(ей) по ID
    async def _delete_user_by_id_async(
        self,
        session: aiohttp.ClientSession,
        user_id: Union[str, int],
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Dict[str, Any]:
        """
        Асинхронное удаление пользователя по ID.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param user_id: Идентификатор пользователя
        :param semaphore: Опциональный семафор для ограничения параллельности
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/users/{user_id}"
        op_name = f"delete_user({user_id})"

        response = await self._make_api_request_async(
            session=session,
            method="DELETE",
            url=url,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        # --- Шаблон ответа ---
        result = {
            "user_id": str(user_id),
            "success": False,
            "error": None,
            "response_data": None,
        }

        # Успех: проверяем поле removed (согласно документации API пользователей)
        if response["success"]:
            data = response["data"] or {}
            removed = data.get("removed", False) if isinstance(data, dict) else False
            if not removed:
                result["error"] = "Пользователь не удален (removed=false)"
                result["response_data"] = data
                return result
            result["success"] = True
            result["response_data"] = data
            return result

        # Ошибки: передаём сообщение из универсальной функции
        result["error"] = response["error"]
        result["response_data"] = response["raw_text"]
        return result

    def delete_user_by_id(
        self,
        user_ids: Union[str, int, List[Union[str, int]]]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Удаление пользователя(ей) по ID.
        Поддерживает одного пользователя (str/int) или список (List[str|int]).
        Для одного пользователя — одиночный запрос, для списка — параллельная обработка.

        :param user_ids: ID пользователя или список ID
        :return: Словарь результата (если один ID) или список словарей (если список)
        """
        # Определяем режим: один пользователь или список
        is_single = isinstance(user_ids, (str, int))
        ids_to_process = [user_ids] if is_single else list(user_ids)

        if not ids_to_process:
            return None if is_single else []

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                tasks = [
                    self._delete_user_by_id_async(session, uid, semaphore)
                    for uid in ids_to_process
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for uid, res in zip(ids_to_process, results):
                    if isinstance(res, Exception):
                        final.append({
                            "user_id": str(uid),
                            "success": False,
                            "error": f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            "response_data": None,
                        })
                    else:
                        final.append(res)
                return final

        results = asyncio.run(run_async())

        # Вывод результатов в лог
        success_count = sum(1 for r in results if r["success"])
        total_count = len(results)

        if is_single:
            res = results[0]
            tag = "[DEL-USER]"
            if res["success"]:
                print(f"{tag} ✓ Пользователь {res['user_id']} удалён успешно")
            else:
                print(f"{tag} ✗ Пользователь {res['user_id']}: {res['error']}")
            return res

        # Пакетный режим
        print(f"[DEL-USERS] ■ Итог: успешно={success_count}/{total_count}")
        for r in results:
            if not r["success"]:
                print(f"  ✗ {r['user_id']}: {r['error']}")

        return results

    # Пользователи
    # Изменяет информацию о сотруднике(ах)
    async def _patch_user_info_async(
        self,
        session: aiohttp.ClientSession,
        uid: Union[str, int],
        user_data: Dict[str, Any],
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Асинхронное обновление информации о сотруднике.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession.
        :param uid: Идентификатор сотрудника (строка или число).
        :param user_data: Словарь с полями для обновления. Возможные поля:
                        - nickname (str): Логин сотрудника
                        - departmentId (int): Идентификатор подразделения
                        - name (dict): ФИО сотрудника {"first": "...", "last": "...", "middle": "..."}
                        - gender (str): Пол сотрудника
                        - position (str): Должность сотрудника
                        - about (str): Описание сотрудника
                        - birthday (str): Дата рождения в формате YYYY-MM-DD
                        - contacts (list): Список контактов
                        - externalId (str): Внешний идентификатор
                        - isAdmin (bool): Признак администратора
                        - isEnabled (bool): Статус аккаунта
                        - timezone (str): Часовой пояс
                        - language (str): Язык сотрудника
                        - password (str): Пароль сотрудника
                        - passwordChangeRequired (bool): Обязательность смены пароля
                        - displayName (str): Публичное имя сотрудника
        :param semaphore: Опциональный семафор для ограничения параллельности.
        :return: Словарь с обновленной информацией о сотруднике или None при ошибке.
        """
        url = f"{self.url}/users/{uid}"
        op_name = f"patch_user({uid})"

        response = await self._make_api_request_async(
            session=session,
            method="PATCH",
            url=url,
            json_data=user_data,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        if response['success']:
            return response['data'] if isinstance(response['data'], dict) else {}

        # При ошибке возвращаем None.
        # Подробная ошибка уже залогирована в _make_api_request_async.
        return None

    def patch_user_info(
        self,
        uid: Union[str, int, List[Tuple[Union[str, int], Dict[str, Any]]]],
        user_data: Optional[Dict[str, Any]] = None,
    ) -> Union[Optional[Dict[str, Any]], List[Optional[Dict[str, Any]]]]:
        """
        Изменяет информацию о сотруднике(ах).
        Изменяются значения только тех параметров, которые были переданы в запросе.
        Поддерживает одиночное обновление (uid + user_data) или пакетное (uid = список [(id, data), ...]).

        :param uid: Идентификатор сотрудника (строка или число) для одиночного обновления.
                    Либо список кортежей [(uid, user_data), ...] для пакетного обновления.
        :param user_data: Словарь с полями для обновления (используется только в одиночном режиме).
                        Возможные поля:
                        - nickname (str): Логин сотрудника
                        - departmentId (int): Идентификатор подразделения
                        - name (dict): ФИО сотрудника {"first": "...", "last": "...", "middle": "..."}
                        - gender (str): Пол сотрудника
                        - position (str): Должность сотрудника
                        - about (str): Описание сотрудника
                        - birthday (str): Дата рождения в формате YYYY-MM-DD
                        - contacts (list): Список контактов
                        - externalId (str): Внешний идентификатор
                        - isAdmin (bool): Признак администратора
                        - isEnabled (bool): Статус аккаунта (true — активен, false — заблокирован).
                                            Используйте для временной блокировки уволенных сотрудников.
                        - isDismissed (bool): ⚠️ УСТАРЕЛО. Поле присутствует в GET-ответе, 
                                                  но НЕ поддерживается для изменения через PATCH API Яндекс 360.
                                                  Для блокировки уволенных используйте isEnabled=False и/или externalId.
                        - timezone (str): Часовой пояс
                        - language (str): Язык сотрудника
                        - password (str): Пароль сотрудника
                        - passwordChangeRequired (bool): Обязательность смены пароля
                        - displayName (str): Публичное имя сотрудника
        :return: Словарь с обновленной информацией о сотруднике или None при ошибке (одиночный режим),
                или список таких результатов (пакетный режим, порядок сохраняется).

        Примеры:
            # Одиночное обновление имени и должности
            result = organization.patch_user_info(
                uid="123456789",
                user_data={
                    "name": {
                        "first": "Иван",
                        "last": "Петров",
                        "middle": "Сергеевич"
                    },
                    "position": "Старший разработчик"
                }
            )

            if result:
                print(f"Обновлено: {result['name']['first']} {result['name']['last']}")
                print(f"Email: {result['email']}")
            else:
                print("Не удалось обновить данные сотрудника")

            # Пакетное обновление (разные данные для каждого пользователя)
            updates = [
                ("111", {"position": "Менеджер"}),
                ("222", {"about": "Обновленное описание"}),
                ("333", {"departmentId": 42}),
            ]
            results = organization.patch_user_info(updates)

            success_count = sum(1 for r in results if r is not None)
            print(f"Успешно обновлено: {success_count} из {len(results)}")

            # Перемещение одного пользователя в другое подразделение
            organization.patch_user_info(uid="987654321", user_data={"departmentId": 456})

            # Блокировка уволенного сотрудника (рекомендуемый подход)
            organization.patch_user_info(
                uid="123456789",
                user_data={
                    "isEnabled": False,
                    "externalId": "DISMISSED-2026-06-01"
                }
            )
        """
        # --- Определяем режим ---
        if isinstance(uid, list):
            # Пакетный режим: uid - это список [(id, data), ...]
            updates_list = uid
            is_batch_mode = True
            if not updates_list:
                print("[PATCH-USERS] ✗ Список обновлений пуст")
                return []
        else:
            # Одиночный режим: uid - ID, user_data - данные
            if not uid:
                print("[PATCH-USER] ✗ uid не может быть пустым")
                return None
            if not user_data:
                print("[PATCH-USER] ✗ user_data не может быть пустым")
                return None
            updates_list = [(uid, user_data)]
            is_batch_mode = False

        # --- Batch-логика прямо в sync-обёртке ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                tasks = [
                    self._patch_user_info_async(session, u, d, semaphore)
                    for u, d in updates_list
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обработка результатов
                final = []
                for (u, d), res in zip(updates_list, results):
                    if isinstance(res, Exception):
                        print(f"[PATCH-USER] ✗ Исключение задачи для пользователя {u}: {res}")
                        final.append(None)
                    else:
                        final.append(res)
                return final

        results = asyncio.run(run_async())

        # --- Вывод и возврат ---
        if is_batch_mode:
            success_count = sum(1 for r in results if r is not None)
            print(f"[PATCH-USERS] ■ Итог: успешно={success_count}/{len(results)}")
            return results
        else:
            res = results[0] if results else None
            if res is not None:
                print(f"[PATCH-USER] ✓ Сотрудник ID:{uid} успешно обновлен")
            return res


    def patch_user_password(self, ids: List):
        """
        Reset to default all users passwords in the list
        :param ids:
        :return:
        """
        data = {
            "password": self.temp_password,
            "passwordChangeRequired": True
        }
        for uid in ids:
            response = requests.patch(f"{self.url}/users/{uid}", json=data, headers=self.headers)
            print(response.text)

    def patch_user_with_unique_password(self, uid: int):
        """
        Reset to default all users passwords in the list
        :param uid:
        :return: password:
        """
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        data = {
            "password": password,
            "passwordChangeRequired": True
        }
        response = requests.patch(f"{self.url}/users/{uid}", json=data, headers=self.headers)
        return password


    # Пользователи
    # Добавление алиаса(ов) почтового ящика сотруднику(ам)
    async def _post_add_user_alias_async(
        self,
        session: aiohttp.ClientSession,
        user_id: Union[str, int],
        alias: str,
        semaphore: asyncio.Semaphore,
    ) -> Dict[str, Any]:
        """
        Асинхронное добавление алиаса почтового ящика сотруднику.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession.
        :param user_id: ID сотрудника (строка или число).
        :param alias: Алиас почтового ящика (например, 'ivan.petrov').
        :param semaphore: Семафор для ограничения параллельности.
        :return: Словарь с результатом операции.
        """
        url = f"{self.url}/users/{user_id}/aliases"
        payload = {"alias": alias}
        op_name = f"add_user_alias({user_id}, {alias})"

        response = await self._make_api_request_async(
            session=session,
            method="POST",
            url=url,
            json_data=payload,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        # --- Шаблон результата ---
        result = {
            "user_id": str(user_id),
            "alias": alias,
            "status": "failed",
            "message": None,
            "details": None,
        }

        # --- Успех: API возвращает полный объект пользователя ---
        if response["success"]:
            result["status"] = "success_retry" if response["retried"] else "success"
            result["message"] = (
                "Алиас добавлен после повторной попытки"
                if response["retried"]
                else "Алиас успешно добавлен"
            )
            result["details"] = response["data"] if isinstance(response["data"], dict) else {}
            return result

        # --- Ошибки: маппинг error_type -> status для вызывающего кода ---
        status_map = {
            "not_found":       ("not_found",     "Сотрудник не найден"),
            "retry_exhausted": ("failed_retry",  f"Ошибка после повтора: {response['error']}"),
            "auth":            ("forbidden",     f"Нет прав доступа: {response['error']}"),
            "http_4xx":        ("bad_request",   f"Некорректный запрос: {response['error']}"),
            "http_5xx":        ("server_error",  f"Ошибка сервера: {response['error']}"),
            "timeout":         ("timeout",       "Тайм-аут соединения"),
            "network":         ("network_error", f"Ошибка сети: {response['error']}"),
            "rate_limited":    ("rate_limited",  "Превышен лимит запросов"),
        }

        status, message = status_map.get(
            response["error_type"],
            ("failed", f"Неожиданная ошибка: {response['error']}")
        )
        result["status"] = status
        result["message"] = message
        return result

    def post_add_user_alias(
        self,
        user_data: Union[
            Tuple[Union[str, int], str],
            List[Tuple[Union[str, int], str]]
        ]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Синхронная обёртка для добавления алиаса(ов) почтового ящика сотруднику(ам).

        :param user_data:
            - Для одного алиаса: кортеж (user_id, alias)
            - Для нескольких: список кортежей [(user_id, alias), ...]
        :return: Словарь результата (один) или список словарей (пакет)

        Примеры:
            # Один алиас
            result = org.post_add_user_alias(("123456", "ivan.petrov"))
            if result['status'] == 'success':
                print(f"Алиас добавлен. Всего алиасов: {len(result['details'].get('aliases', []))}")
            else:
                print(f"Ошибка: {result['message']}")

            # Пакетное добавление
            aliases_to_add = [
                ("111", "sales"),
                ("222", "support"),
                ("333", "info"),
            ]
            results = org.post_add_user_alias(aliases_to_add)

            success_count = sum(1 for r in results if r['status'].startswith('success'))
            print(f"Успешно добавлено: {success_count} из {len(results)}")
        """
        # --- Определяем режим: одиночный или пакетный ---
        is_single = (
            isinstance(user_data, tuple)
            and len(user_data) == 2
            and isinstance(user_data[1], str)
        )

        if is_single:
            items = [user_data]
            single_request = True
        elif isinstance(user_data, list):
            items = list(user_data)
            single_request = False
        else:
            raise TypeError(
                "Ожидается кортеж (user_id, alias) или список таких кортежей"
            )

        if not items:
            return None if single_request else []

        # --- Предварительная валидация ---
        valid_tasks = []
        for uid, alias in items:
            if not uid:
                valid_tasks.append({
                    "user_id": str(uid) if uid else "unknown",
                    "alias": alias,
                    "status": "validation_error",
                    "message": "user_id не может быть пустым",
                    "_early_error": True
                })
            elif not alias or not isinstance(alias, str):
                valid_tasks.append({
                    "user_id": str(uid),
                    "alias": alias,
                    "status": "validation_error",
                    "message": "alias должен быть непустой строкой",
                    "_early_error": True
                })
            else:
                valid_tasks.append((uid, alias))

        network_tasks = [t for t in valid_tasks if isinstance(t, tuple)]

        # --- Batch-логика прямо здесь, без промежуточного async-метода ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []

            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                tasks = [
                    self._post_add_user_alias_async(session, uid, alias, semaphore)
                    for uid, alias in network_tasks
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                final = []
                for (uid, alias), res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            "user_id": str(uid),
                            "alias": alias,
                            "status": "error",
                            "message": f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                        })
                    else:
                        final.append(res)
                return final

        net_results = asyncio.run(run_async())

        # --- Собираем финальный список в исходном порядке ---
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get("_early_error"):
                item.pop("_early_error", None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    "user_id": str(item[0]),
                    "alias": item[1],
                    "status": "error",
                    "message": "Нет результата выполнения"
                })

        # --- Возврат результата ---
        if single_request:
            return final_results[0] if final_results else {
                "user_id": str(items[0][0]),
                "alias": items[0][1],
                "status": "error",
                "message": "Не удалось выполнить запрос"
            }

        return final_results

    # Пользователи
    # Удаление алиаса(ов) почтового ящика у сотрудника(ов)
    async def delete_user_alias_async(
        self,
        session: aiohttp.ClientSession,
        user_id: str,
        alias: str,
        semaphore: asyncio.Semaphore,
    ) -> dict:
        """
        Асинхронное удаление алиаса с использованием переданной сессии.
        
        :param session: Активный aiohttp.ClientSession
        :param user_id: ID пользователя
        :param alias: Алиас для удаления
        :param semaphore: Семафор для ограничения параллельности
        :return: Словарь с результатом
        """
        url = f"{self.url}/users/{user_id}/aliases/{alias}"
        
        response = await self._make_api_request_async(
            session=session,
            method="DELETE",
            url=url,
            semaphore=semaphore,
            operation_name=f"delete_alias({alias}, user={user_id})",
        )

        base = {"user_id": user_id, "alias": alias}

        if response['success']:
            removed = (response['data'] or {}).get('removed', False)
            return {
                **base,
                "status": "success" if removed else "failed",
                "message": "Удалено успешно" if removed else "Алиас не удален (removed=false)",
                "details": response['data'],
            }

        # Маппинг error_type → status для вызывающего кода
        status_map = {
            "not_found": "not_found",
            "retry_exhausted": "failed_retry",
            "auth": "forbidden",
            "http_4xx": "bad_request",
            "http_5xx": "server_error",
            "timeout": "timeout",
            "network": "network_error",
        }
        return {
            **base,
            "status": status_map.get(response['error_type'], "failed"),
            "message": response['error'],
            "retried": response['retried'],
            "details": response['data'] or response['raw_text'],
        }

    def delete_user_alias(
        self,
        user_data: Union[
            Tuple[Union[str, int], str],
            List[Tuple[Union[str, int], str]]
        ]
    ) -> Union[dict, List[dict]]:
        """
        Синхронная обёртка для удаления алиаса(ов) почтового ящика у сотрудника(ов).

        :param user_data:
            - Для одного алиаса: кортеж (user_id, alias)
            - Для нескольких: список кортежей [(user_id, alias), ...]
        :return: Словарь результата (один) или список словарей (пакет)

        Примеры:
            # Один алиас
            result = org.delete_user_alias(("123456", "ivan.petrov"))
            if result['status'] == 'success':
                print(f"Алиас удалён")
            else:
                print(f"Ошибка: {result['message']}")

            # Пакетное удаление
            aliases_to_delete = [
                ("111", "old-alias-1"),
                ("222", "old-alias-2"),
                ("333", "deprecated"),
            ]
            results = org.delete_user_alias(aliases_to_delete)

            success_count = sum(1 for r in results if r['status'] == 'success')
            print(f"Успешно удалено: {success_count} из {len(results)}")
        """
        # Определяем: одиночный вызов или пакетный
        is_single = (
            isinstance(user_data, tuple)
            and len(user_data) == 2
            and isinstance(user_data[1], str)
        )

        if is_single:
            items = [user_data]
            single_request = True
        elif isinstance(user_data, list):
            items = list(user_data)
            single_request = False
        else:
            raise TypeError(
                "Ожидается кортеж (user_id, alias) или список таких кортежей"
            )

        if not items:
            return None if single_request else []

        # Предварительная валидация
        valid_tasks = []
        for uid, alias in items:
            if not uid:
                valid_tasks.append({
                    "user_id": str(uid) if uid else "unknown",
                    "alias": alias,
                    "status": "validation_error",
                    "message": "user_id не может быть пустым",
                    "_early_error": True
                })
            elif not alias or not isinstance(alias, str):
                valid_tasks.append({
                    "user_id": str(uid),
                    "alias": alias,
                    "status": "validation_error",
                    "message": "alias должен быть непустой строкой",
                    "_early_error": True
                })
            else:
                valid_tasks.append((uid, alias))

        network_tasks = [t for t in valid_tasks if isinstance(t, tuple)]

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []
            
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)
                
                tasks = [
                    self.delete_user_alias_async(session, uid, alias, semaphore)
                    for uid, alias in network_tasks
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                final = []
                for (uid, alias), res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            "user_id": str(uid),
                            "alias": alias,
                            "status": "error",
                            "message": f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                        })
                    else:
                        final.append(res)
                return final

        net_results = asyncio.run(run_async())

        # Собираем финальный список в исходном порядке
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get("_early_error"):
                item.pop("_early_error", None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    "user_id": str(item[0]),
                    "alias": item[1],
                    "status": "error",
                    "message": "Нет результата выполнения"
                })

        if single_request:
            return final_results[0] if final_results else {
                "user_id": str(items[0][0]),
                "alias": items[0][1],
                "status": "error",
                "message": "Не удалось выполнить запрос"
            }

        return final_results


    # Пользователи
    # Изменение контактной информации сотрудника
    async def _patch_user_contacts_async(
        self,
        session: aiohttp.ClientSession,
        user_id: Union[str, int],
        contacts_data: Union[List[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Асинхронное изменение контактной информации сотрудника (полная замена, PUT).
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        ⚠️ ВАЖНО: автоматически созданную контактную информацию (с флагом `synthetic`)
        нельзя изменить или удалить — она управляется системой (например, на основе алиасов).
        Передавайте только контакты, созданные вручную (email, phone, site, icq, twitter, skype, phone_extension).

        :param session: Активный aiohttp.ClientSession.
        :param user_id: Идентификатор сотрудника (строка или число).
        :param contacts_data: Либо список контактов, либо готовый dict с ключом 'contacts'.
                            Каждый контакт: {"type": "...", "value": "...", "label": "..."}
                            Возможные типы: email, phone, phone_extension, site, icq, twitter, skype
        :return: Словарь с результатом операции:
                {
                    'user_id': str,
                    'success': bool,
                    'error': str | None,
                    'response_data': dict | str | None,
                    'message': str | None
                }

        Примеры payload:
            # Вариант 1: список контактов (метод сам обернёт в {"contacts": [...]})
            [
                {"type": "phone", "value": "+79001234567", "label": "Мобильный"},
                {"type": "email", "value": "personal@example.com", "label": "Личный"},
                {"type": "site",  "value": "https://linkedin.com/in/user"}
            ]

            # Вариант 2: готовый payload
            {
                "contacts": [
                    {"type": "phone", "value": "+79001234567"}
                ]
            }
        """
        url = f"{self.url}/users/{user_id}/contacts"
        op_name = f"patch_user_contacts({user_id})"

        # --- Нормализация формата данных для API ---
        # API требует, чтобы корневой элемент был JSON-объектом (message),
        # а не массивом. Принимаем оба формата для гибкости.
        if isinstance(contacts_data, list):
            payload = {"contacts": contacts_data}
        elif isinstance(contacts_data, dict) and "contacts" in contacts_data:
            payload = contacts_data
        else:
            return {
                'user_id': str(user_id),
                'success': False,
                'error': (
                    f"Некорректный формат contacts_data: ожидается list или dict с ключом 'contacts', "
                    f"получено {type(contacts_data).__name__}"
                ),
                'response_data': None,
                'message': None,
            }

        response = await self._make_api_request_async(
            session=session,
            method="PUT",
            url=url,
            json_data=payload,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,  # семафором управляет batch-обёртка снаружи
        )

        # --- Минимальный маппинг под контракт вызывающего кода ---
        result = {
            'user_id': str(user_id),
            'success': response['success'],
            'error': response['error'],
            'response_data': response['data'] if response['success'] else response['raw_text'],
            'message': None,
        }

        # Бизнес-специфика: человекочитаемое message при успехе
        if response['success']:
            base_msg = "Контакты успешно обновлены"
            if not response['data']:
                base_msg += " (пустой ответ)"
            if response['retried']:
                base_msg += " (после повтора)"
            result['message'] = base_msg

        return result

    def patch_user_contacts(
        self,
        user_contacts: Union[
            Tuple[Union[str, int], Union[List[Dict[str, Any]], Dict[str, Any]]],
            List[Tuple[Union[str, int], Union[List[Dict[str, Any]], Dict[str, Any]]]]
        ]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Синхронная обёртка для изменения контактной информации сотрудника(ов).
        Поддерживает одного сотрудника (кортеж) или список сотрудников (список кортежей).

        ⚠️ ВАЖНО: автоматически созданную контактную информацию (с флагом `synthetic`)
        нельзя изменить или удалить — она управляется системой.
        Передавайте только контакты, созданные вручную.

        :param user_contacts:
            - Для одного сотрудника: кортеж (user_id, contacts_data),
            где contacts_data — либо list[dict], либо dict с ключом 'contacts'
            - Для списка сотрудников: список кортежей [(user_id, contacts_data), ...]
        :return: Словарь результата (если один) или список словарей (если список).

        Примеры:
            # Один сотрудник, список контактов
            result = organization.patch_user_contacts((
                "123456789",
                [
                    {"type": "phone", "value": "+79001234567", "label": "Мобильный"},
                    {"type": "site",  "value": "https://linkedin.com/in/user"}
                ]
            ))
            if result['success']:
                print(f"Контакты сотрудника {result['user_id']} обновлены")
            else:
                print(f"Ошибка: {result['error']}")

            # Пакетное обновление разных сотрудников
            results = organization.patch_user_contacts([
                ("111", [{"type": "phone", "value": "+79001111111"}]),
                ("222", [{"type": "email", "value": "work@example.com", "label": "Рабочий"}]),
                ("333", {"contacts": [{"type": "site", "value": "https://example.com"}]}),
            ])

            success_count = sum(1 for r in results if r['success'])
            print(f"Успешно: {success_count} из {len(results)}")

            for r in results:
                if not r['success']:
                    print(f"  ✗ {r['user_id']}: {r['error']}")

            # Очистка всех контактов сотрудника (пустой список)
            organization.patch_user_contacts(("123456789", []))
        """
        # --- Определяем режим: одиночный или пакетный ---
        is_single = (
            isinstance(user_contacts, tuple)
            and len(user_contacts) == 2
            and isinstance(user_contacts[0], (str, int))
        )

        if is_single:
            items = [user_contacts]
            single_request = True
        elif isinstance(user_contacts, list):
            items = list(user_contacts)
            single_request = False
        else:
            raise TypeError(
                "Ожидается кортеж (user_id, contacts_data) "
                "или список таких кортежей [(user_id, contacts_data), ...]"
            )

        if not items:
            return None if single_request else []

        # --- Предварительная валидация и нормализация ---
        # Элементы будут либо кортежем (uid, contacts), либо словарём-ошибкой валидации
        valid_tasks = []
        for uid, contacts in items:
            if not uid:
                valid_tasks.append({
                    'user_id': str(uid) if uid else "unknown",
                    'success': False,
                    'error': "user_id не может быть пустым",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            # Принимаем оба валидных формата: list или dict с ключом 'contacts'
            if isinstance(contacts, list):
                # Базовая проверка структуры элементов
                if contacts and not all(isinstance(c, dict) for c in contacts):
                    valid_tasks.append({
                        'user_id': str(uid),
                        'success': False,
                        'error': "Каждый контакт должен быть словарём (dict)",
                        'response_data': None,
                        'message': None,
                        '_early_error': True,
                    })
                    continue
                valid_tasks.append((uid, contacts))
            elif isinstance(contacts, dict) and 'contacts' in contacts:
                valid_tasks.append((uid, contacts))
            else:
                valid_tasks.append({
                    'user_id': str(uid),
                    'success': False,
                    'error': (
                        f"contacts_data должен быть списком (list) или dict с ключом 'contacts', "
                        f"получено {type(contacts).__name__}"
                    ),
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })

        # Разделяем валидные сетевые задачи и заранее ошибочные результаты
        network_tasks = [t for t in valid_tasks if isinstance(t, tuple)]
        # early_errors остаются в valid_tasks как dict'ы с '_early_error'

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []

            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                async def bounded_patch(uid, contacts):
                    async with semaphore:
                        await asyncio.sleep(random.uniform(0.01, 0.05))  # jitter
                        return await self._patch_user_contacts_async(session, uid, contacts)

                tasks = [bounded_patch(uid, contacts) for uid, contacts in network_tasks]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                final = []
                for (uid, _), res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            'user_id': str(uid),
                            'success': False,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'response_data': None,
                            'message': None,
                        })
                    else:
                        final.append(res)
                return final

        net_results = asyncio.run(run_async())

        # --- Собираем финальный список в исходном порядке ---
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get('_early_error'):
                item.pop('_early_error', None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    'user_id': str(item[0]),
                    'success': False,
                    'error': "Нет результата выполнения",
                    'response_data': None,
                    'message': None,
                })

        # --- Вывод результатов в лог ---
        if single_request:
            res = final_results[0] if final_results else None
            tag = "[PATCH-USER-CONTACTS]"
            if res and res['success']:
                print(f"{tag} ✓ Сотрудник {res['user_id']}: {res['message']}")
            elif res:
                print(f"{tag} ✗ Сотрудник {res['user_id']}: {res['error']}")
            return res

        # Пакетный режим
        success_count = sum(1 for r in final_results if r and r['success'])
        total_count = len(final_results)
        print(f"[PATCH-USER-CONTACTS-BATCH] ■ Итог: успешно={success_count}/{total_count}")
        for r in final_results:
            if r and not r['success']:
                print(f"  ✗ {r['user_id']}: {r['error']}")

        return final_results


    # Пользователи
    # Удаление контактной информации (внесённой вручную) у сотрудника
    async def _delete_user_contact_single_async(
        self,
        session: aiohttp.ClientSession,
        user_id: Union[str, int],
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Dict[str, Any]:
        """
        Асинхронное удаление контактной информации (внесённой вручную) у одного сотрудника.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        Примечание: автоматически созданную контактную информацию (с флагом `synthetic`)
        удалить нельзя — API просто оставит её нетронутой.

        :param session: Активный aiohttp.ClientSession.
        :param user_id: Идентификатор сотрудника (строка или число).
        :param semaphore: Опциональный семафор для ограничения параллельности.
        :return: Словарь с результатом операции:
                {
                    'id': str,           # ID сотрудника
                    'success': bool,     # True при успешном удалении
                    'error': str | None, # Сообщение об ошибке (None при успехе)
                    'response_data': dict | None  # Полный объект пользователя или raw-текст ошибки
                }
        """
        url = f"{self.url}/users/{user_id}/contacts"
        op_name = f"delete_contacts({user_id})"

        response = await self._make_api_request_async(
            session=session,
            method="DELETE",
            url=url,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        # --- Шаблон результата ---
        result = {
            'id': str(user_id),
            'success': False,
            'error': None,
            'response_data': None,
        }

        if response['success']:
            result['success'] = True
            result['response_data'] = response['data'] if isinstance(response['data'], dict) else {}
            return result

        # --- Ошибки: используем сообщение из универсальной функции ---
        result['error'] = response['error']
        result['response_data'] = response['raw_text']
        return result

    def delete_user_contact(
        self,
        user_ids: Union[str, int, List[Union[str, int]]]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Синхронная обёртка для удаления контактной информации (внесённой вручную) у сотрудников.
        Поддерживает одного сотрудника (str/int) или список сотрудников (List[str|int]).
        Для одного сотрудника — одиночный запрос, для списка — параллельная обработка.

        Примечание: автоматически созданную контактную информацию (с флагом `synthetic`)
        удалить нельзя — API просто оставит её нетронутой.

        :param user_ids: ID сотрудника (str/int) или список ID (List[str|int]).
        :return: Словарь результата (если один ID) или список словарей (если список).
                Каждый словарь: {'id': str, 'success': bool, 'error': str|None, 'response_data': dict|None}

        Примеры:
            # Один сотрудник
            result = organization.delete_user_contact("123456789")
            if result['success']:
                print(f"Контакты сотрудника {result['id']} удалены")
            else:
                print(f"Ошибка: {result['error']}")

            # Пакетное удаление
            results = organization.delete_user_contact(["111", "222", "333"])
            success_count = sum(1 for r in results if r['success'])
            print(f"Успешно: {success_count} из {len(results)}")

            for r in results:
                if not r['success']:
                    print(f"  ✗ {r['id']}: {r['error']}")
        """
        # --- Определяем режим: одиночный или пакетный ---
        is_single = isinstance(user_ids, (str, int))
        ids_to_process = [user_ids] if is_single else list(user_ids)

        if not ids_to_process:
            return None if is_single else []

        # --- Batch-логика прямо в sync-обёртке ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                tasks = [
                    self._delete_user_contact_single_async(session, uid, semaphore)
                    for uid in ids_to_process
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for uid, res in zip(ids_to_process, results):
                    if isinstance(res, Exception):
                        final.append({
                            'id': str(uid),
                            'success': False,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'response_data': None,
                        })
                    else:
                        final.append(res)
                return final

        results = asyncio.run(run_async())

        # --- Вывод результатов в лог ---
        if is_single:
            res = results[0]
            tag = "[DEL-CONTACTS]"
            if res['success']:
                print(f"{tag} ✓ Контакты сотрудника {res['id']} удалены")
            else:
                print(f"{tag} ✗ Сотрудник {res['id']}: {res['error']}")
            return res

        # Пакетный режим
        success_count = sum(1 for r in results if r['success'])
        total_count = len(results)
        print(f"[DEL-CONTACTS-BATCH] ■ Итог: успешно={success_count}/{total_count}")
        for r in results:
            if not r['success']:
                print(f"  ✗ {r['id']}: {r['error']}")

        return results

    def get_user_2fa(self, uid):
        response = requests.get(f"{self.url}/users/{uid}/2fa", headers=self.headers)
        return response.json()


    # Правила
    def get_email_rules(self):
        response = requests.get(f"{self.url_rules}", headers=self.headers)
        print(response)


    # Публичные ссылки
    def get_public_links(self):
        """
        get all public resources shared by users in organization
        """
        return asyncio.run(self.get_public_links_async(self.get_all_users_id()))

    async def get_public_links_async(self, users_list):

        async with aiohttp.ClientSession("https://api360.yandex.net", headers=self.headers) as session:
            public_resources = {}
            for user_id in users_list:
                user_public_resources = []
                page_num = 1
                params = {
                    'orgId': self.org_id,
                    'userId': user_id,
                    'page': page_num
                }
                async with session.get('/admin/v1/disk/resources/public', params=params) as resp:
                    try:
                        resp_json = dict(await resp.json())
                        print(f"User id {user_id} responses: {resp_json}")
                        while resp_json.get("resources"):
                            user_public_resources.extend(resp_json.get("resources"))
                            page_num += 1
                            params = {
                                'orgId': self.org_id,
                                'userId': user_id,
                                'page': page_num
                            }
                            async with session.get('/admin/v1/disk/resources/public', params=params,
                                                   headers=self.headers) as resp_add:
                                resp_json = dict(await resp_add.json())
                                print(f"User id {user_id} responses: {resp_json}")
                    except aiohttp.client_exceptions.ContentTypeError as e:
                        print(f"Error occured: {e}")
                    except requests.exceptions.JSONDecodeError as e:
                        print(f"Error occured: {e}")
                if len(user_public_resources):
                    public_resources[user_id] = user_public_resources
        return public_resources


    def wipe_all_groups(self):
        for id in list(x.get('id') for x in self.get_groups_list()):
            print(self.delete_group_by_id(id))

    def wipe_all_departments(self):
        for id in list(x.get('id') for x in self.get_departments_list()):
            self.delete_department_by_id(id)


    @staticmethod
    def save_file(file_name, data):
        if isinstance(data, List):
            with open(f"{file_name}.txt", "w", encoding='utf-16') as output:
                for d in data:
                    output.write(f"{d}\n")
        else:
            with open(f'{file_name}.csv', 'w', encoding='utf-16', newline='') as csv_file:
                fieldnames = data[0].keys()
                writer = csv.DictWriter(csv_file, delimiter=',', fieldnames=fieldnames)
                writer.writeheader()
                for user in data:
                    writer.writerow(user)


    # Внешние контакты
    async def _get_external_contacts_async_page(
        self,
        session: aiohttp.ClientSession,
        page: int,
        semaphore: asyncio.Semaphore
    ) -> dict:
        """
        Внутренний метод для асинхронного получения одной страницы внешних контактов.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param page: Номер страницы для загрузки
        :param semaphore: Семафор для ограничения параллельности (передаётся извне)
        :return: Словарь с данными страницы (contacts, page, pages, total) или {} при ошибке
        """
        url = f"{self.url}/external_contacts"
        op_name = f"get_ext_contacts_page({page})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            params={'page': page, 'perPage': 100},
            semaphore=semaphore,      # Семафор передаётся извне, как в оригинале
            operation_name=op_name,
            retry_on_500=True,        # Улучшение: добавлен retry для идемпотентного GET
            max_retries=1,
            retry_delay=1.0,
            jitter=False,             # В оригинале jitter не было — сохраняем поведение
        )

        # Контракт возврата: словарь страницы или {} при ошибке.
        # Это важно для совместимости с get_external_contacts_async,
        # который проверяет first_page.get('contacts', []).
        if response['success'] and isinstance(response['data'], dict):
            return response['data']
        return {}

    async def get_external_contacts_async(self) -> Optional[list]:
        """
        Асинхронное ПАРАЛЛЕЛЬНОЕ получение всех внешних контактов организации.
        Определяет общее количество страниц по первому запросу, а остальные скачивает одновременно.

        :return: Список словарей с данными контактов или None при ошибке получения первой страницы.
                 Если контактов нет, возвращает [].
        """
        all_contacts = []
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

        async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
            # Загружаем первую страницу для получения метаданных (узнаем сколько всего страниц)
            first_page = await self._get_external_contacts_async_page(session, 1, semaphore)
            
            # КРИТИЧЕСКОЕ ИЗМЕНЕНИЕ: если первая страница не получена (ошибка), возвращаем None
            if not first_page:
                return None
            
            contacts = first_page.get('contacts', [])
            if not contacts:
                # Успешно получена первая страница, но контактов нет
                return []
                
            all_contacts.extend(contacts)
            total_pages = first_page.get('pages', 1) or 1  # Защита от None
            
            # Если страниц больше одной, запускаем сбор остальных параллельно
            if total_pages > 1:
                tasks = [
                    self._get_external_contacts_async_page(session, p, semaphore)
                    for p in range(2, total_pages + 1)
                ]
                pages_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for data in pages_results:
                    if isinstance(data, dict):
                        all_contacts.extend(data.get('contacts', []))
                    elif isinstance(data, Exception):
                        print(f"Исключение задачи во время параллельной загрузки внешних контактов: {data}")
                    
        return all_contacts

    def get_external_contacts(self) -> Optional[list]:
        """
        Синхронный менеджер для удобного запуска параллельного асинхронного скачивания.
        Используется как обёртка над get_external_contacts_async.

        :return: Список словарей с данными контактов, [] если контактов нет,
                 или None при ошибке получения первой страницы.

        Примеры:
            contacts = organization.get_external_contacts()
            if contacts is None:
                print("Ошибка загрузки контактов")
            else:
                print(f"Загружено контактов: {len(contacts)}")
        """
        try:
            return asyncio.run(self.get_external_contacts_async())
        except RuntimeError as e:
            # Защита от вызова внутри уже активного event loop
            print(f"[EXT-CONTACTS] ✗ RuntimeError: {e}")
            return None
        except Exception as e:
            print(f"[EXT-CONTACTS] ✗ Неожиданная ошибка: {type(e).__name__}: {e}")
            return None

    @staticmethod
    def _validate_contact_data(contact_data: dict) -> Tuple[bool, str]:
        """
        Базовая валидация данных внешнего контакта перед отправкой в API.
        Проверяет обязательное наличие и структуру поля 'emails'.
        
        :param contact_data: Словарь с данными контакта
        :return: Кортеж (True, "") если ок, или (False, "Текст ошибки")
        """
        if not isinstance(contact_data, dict):
            return False, "Данные контакта должны быть словарем (dict)"
        
        if not contact_data.get('emails'):
            return False, "Поле 'emails' обязательно и не может быть пустым"
        
        # Проверка структуры первого email
        email_list = contact_data.get('emails', [])
        if email_list and isinstance(email_list[0], dict):
            if 'email' not in email_list[0]:
                return False, "В массиве 'emails' отсутствует поле 'email'"
        
        return True, ""

    async def _post_external_contact_async(
        self,
        session: aiohttp.ClientSession,
        contact_data: dict,
    ) -> dict:
        """
        Асинхронное добавление нового внешнего контакта.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param contact_data: Словарь с данными контакта
        :return: Словарь с результатом операции
        """
        url = f"{self.url}/external_contacts"

        first = contact_data.get('firstName', '')
        last = contact_data.get('lastName', '')
        op_name = f"post_external_contact({first} {last})".strip() or "post_external_contact"

        response = await self._make_api_request_async(
            session=session,
            method="POST",
            url=url,
            json_data=contact_data,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            jitter=False,  # jitter делает batch-обёртка снаружи
        )

        if response['success']:
            data = response['data'] or {}
            return {
                'success': True,
                'contact_id': data.get('id') if isinstance(data, dict) else None,
                'error': None,
                'response_data': data,
            }

        return {
            'success': False,
            'contact_id': None,
            'error': response['error'],
            'response_data': response['raw_text'] or response['data'],
            'status': 'failed_retry' if response['error_type'] == 'retry_exhausted' else 'failed',
        }

    def post_create_external_contacts_batch(self, contacts_data_list: List[dict]) -> List[dict]:
        """
        Синхронная обертка для пакетного добавления внешних контактов.
        Гарантирует строгое соответствие индексов входных данных и результатов.
        Использует asyncio.gather для параллельной обработки с контролем конкурентности.

        :param contacts_data_list: Список словарей с данными контактов.
        :return: Список результатов в том же порядке, что и входные данные.
        """
        if not contacts_data_list:
            return []

        # 1. Предварительная валидация (early errors)
        valid_tasks = []
        for data in contacts_data_list:
            if not isinstance(data, dict):
                valid_tasks.append({
                    'success': False,
                    'contact_id': None,
                    'error': f"Некорректный тип данных: {type(data).__name__}",
                    'response_data': None,
                    '_early_error': True,
                })
                continue

            is_valid, error_msg = self._validate_contact_data(data)
            if not is_valid:
                valid_tasks.append({
                    'success': False,
                    'contact_id': None,
                    'error': f"Валидация: {error_msg}",
                    'response_data': None,
                    '_early_error': True,
                })
            else:
                # Валидные данные отправляем в сеть
                valid_tasks.append(data)

        network_tasks = [t for t in valid_tasks if not (isinstance(t, dict) and t.get('_early_error'))]

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []

            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                async def bounded_post(data):
                    async with semaphore:
                        # Jitter: рассинхронизация старта запросов
                        await asyncio.sleep(random.uniform(0.01, 0.05))
                        return await self._post_external_contact_async(session, data)

                tasks = [bounded_post(data) for data in network_tasks]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final_net_results = []
                for res in results:
                    if isinstance(res, Exception):
                        final_net_results.append({
                            'success': False,
                            'contact_id': None,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'response_data': None,
                        })
                    else:
                        final_net_results.append(res)
                return final_net_results

        net_results = asyncio.run(run_async())

        # 2. Склеиваем результаты, сохраняя исходный порядок
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get('_early_error'):
                item.pop('_early_error', None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    'success': False,
                    'contact_id': None,
                    'error': 'Нет результата выполнения',
                    'response_data': None,
                })

        success = sum(1 for r in final_results if r.get('success'))
        total = len(final_results)
        print(f"[BATCH-EXT-CONTACTS] ■ Итог: успешно={success}/{total}")

        return final_results


    async def _get_external_contact_info_async(
        self,
        session: aiohttp.ClientSession,
        contact_id: str
    ) -> Dict[str, Any]:
        """
        Асинхронное получение информации об одном внешнем контакте.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param contact_id: Идентификатор внешнего контакта
        :return: Словарь с результатом (контракт сохранён: id, success, error, data)
        """
        url = f"{self.url}/external_contacts/{contact_id}"
        op_name = f"get_ext_contact({contact_id})"

        response = await self._make_api_request_async(
            session=session,
            method="GET",
            url=url,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,
        )

        return {
            'id': contact_id,
            'success': response['success'],
            'error': response['error'],
            'data': response['data'] if response['success'] else None,
        }

    def get_external_contacts_info_batch(
        self,
        contact_ids: Union[str, List[str]]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Получение информации о внешних контактах (одиночное или пакетное).
        Поддерживает один ID (str) или список ID (List[str]).
        Для одного контакта — одиночный запрос, для списка — параллельная обработка.

        :param contact_ids: ID контакта (str) или список ID (List[str])
        :return: Словарь результата (если один ID) или список словарей (если список)

        Примеры:
            # Один контакт
            result = organization.get_external_contacts_info_batch("abc123")
            if result['success']:
                print(f"Контакт: {result['data'].get('firstName')}")
            else:
                print(f"Ошибка: {result['error']}")

            # Пакетное получение
            results = organization.get_external_contacts_info_batch(["abc123", "def456", "nonexistent"])
            success_count = sum(1 for r in results if r['success'])
            print(f"Успешно: {success_count} из {len(results)}")
        """
        # Определяем режим: один контакт или список
        is_single = isinstance(contact_ids, str)
        ids_to_process = [contact_ids] if is_single else list(contact_ids)

        if not ids_to_process:
            return None if is_single else []

        # Batch-логика прямо в sync-обёртке
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                async def bounded_get(contact_id):
                    async with semaphore:
                        await asyncio.sleep(random.uniform(0.01, 0.05))  # jitter
                        return await self._get_external_contact_info_async(session, contact_id)

                tasks = [bounded_get(cid) for cid in ids_to_process]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for cid, res in zip(ids_to_process, results):
                    if isinstance(res, Exception):
                        final.append({
                            'id': cid,
                            'success': False,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'data': None
                        })
                    else:
                        final.append(res)
                return final

        results = asyncio.run(run_async())

        # Вывод результатов
        if is_single:
            res = results[0]
            tag = "[EXT-CONTACT-GET]"
            if res['success']:
                print(f"{tag} ✓ Контакт {res['id']} получен")
            else:
                print(f"{tag} ✗ Контакт {res['id']}: {res['error']}")
            return res

        # Пакетный режим
        success_count = sum(1 for r in results if r['success'])
        total_count = len(results)
        print(f"[EXT-CONTACTS-BATCH] ■ Итог: успешно={success_count}/{total_count}")
        for r in results:
            if not r['success']:
                print(f"  ✗ {r['id']}: {r['error']}")

        return results


    async def _delete_external_contact_single_async(
        self,
        session: aiohttp.ClientSession,
        contact_id: str,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> dict:
        """
        Асинхронное удаление внешнего контакта.
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.
        
        Специфика endpoint'а: контракт возврата использует поле `status` (а не `success`)
        для обратной совместимости с вызывающим кодом синхронизации.

        :param session: Активный aiohttp.ClientSession
        :param contact_id: Идентификатор внешнего контакта (string)
        :param semaphore: Семафор для ограничения параллельности
        :return: Словарь с результатом операции:
                 {
                     'contact_id': str,
                     'status': 'success' | 'success_retry' | 'not_found' | 'unauthorized' | 
                               'forbidden' | 'failed' | 'failed_retry' | 'error',
                     'message': str | None
                 }
        """
        url = f"{self.url}/external_contacts/{contact_id}"
        op_name = f"delete_ext_contact({contact_id})"

        response = await self._make_api_request_async(
            session=session,
            method="DELETE",
            url=url,
            semaphore=semaphore,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
        )

        # --- Шаблон ответа с бизнес-специфичными статусами ---
        result = {
            "contact_id": contact_id,
            "status": "failed",
            "message": None,
        }

        # Успех: HTTP 200 — контакт удалён (API внешних контактов не возвращает поле `removed`)
        if response["success"]:
            result["status"] = "success_retry" if response["retried"] else "success"
            result["message"] = (
                "Удалено после повторной попытки"
                if response["retried"]
                else "Контакт удалён успешно"
            )
            return result

        # --- Маппинг error_type → специфичные status для обратной совместимости ---
        # Вызывающий код проверяет:
        #   r.get('status') in ['success', 'not_found']
        # поэтому эти статусы должны быть сохранены.
        status_map = {
            "not_found":       ("not_found",   "Контакт не найден"),
            "retry_exhausted": ("failed_retry", f"Ошибка после повтора: {response['error']}"),
            "timeout":         ("error",       "Тайм-аут соединения"),
            "network":         ("error",       f"Ошибка сети: {response['error']}"),
        }

        # Авторизация — зависит от HTTP-кода
        if response["error_type"] == "auth":
            if response["status_code"] == 401:
                result["status"] = "unauthorized"
                result["message"] = "Пользователь не авторизован"
                return result
            if response["status_code"] == 403:
                result["status"] = "forbidden"
                result["message"] = "Нет прав на удаление"
                return result

        # Применяем таблицу маппинга
        if response["error_type"] in status_map:
            result["status"], result["message"] = status_map[response["error_type"]]
            return result

        # Все остальные ошибки (400, 429, 5xx без retry, unexpected и т.д.)
        result["status"] = "failed"
        result["message"] = f"Неожиданная ошибка API: {response['error']}"
        return result

    def delete_external_contact(
        self,
        contact_ids: Union[str, List[str]],
    ) -> Union[dict, List[dict]]:
        """
        Синхронная обёртка для удаления внешних контактов.
        Поддерживает удаление одного контакта (str) или списка контактов (List[str]).
        Для одного контакта — одиночный запрос, для списка — параллельная обработка.

        :param contact_ids: ID контакта (str) или список ID (List[str])
        :return: Словарь результата (если один ID) или список словарей (если список).
                 Каждый словарь: {'contact_id': str, 'status': str, 'message': str|None}
                 
                 Возможные значения status:
                 - 'success'        — контакт успешно удалён
                 - 'success_retry'  — контакт удалён после повторной попытки
                 - 'not_found'      — контакт не найден (считается успехом в sync-коде)
                 - 'unauthorized'   — 401, не авторизован
                 - 'forbidden'      — 403, нет прав
                 - 'failed'         — общая ошибка API
                 - 'failed_retry'   — ошибка после исчерпания retry
                 - 'error'          — сетевая ошибка / тайм-аут
                 - 'validation_error' — ошибка валидации входных данных

        Примеры:
            # Один контакт
            result = organization.delete_external_contact("abc123")
            if result['status'] in ['success', 'not_found']:
                print(f"Контакт {result['contact_id']} удалён")
            else:
                print(f"Ошибка: {result['message']}")

            # Пакетное удаление
            results = organization.delete_external_contact(["abc", "def", "xyz"])
            success = sum(1 for r in results if r['status'] in ['success', 'not_found'])
            print(f"Успешно: {success} из {len(results)}")
        """
        # --- Определяем режим: одиночный или пакетный ---
        if isinstance(contact_ids, str):
            ids_to_process = [contact_ids]
            single_request = True
        elif isinstance(contact_ids, list):
            ids_to_process = list(contact_ids)
            single_request = False
        else:
            raise TypeError(
                f"Ожидается str или List[str], получено {type(contact_ids).__name__}"
            )

        if not ids_to_process:
            return None if single_request else []

        # --- Предварительная валидация (early errors) ---
        valid_tasks = []
        for cid in ids_to_process:
            if not cid or not isinstance(cid, str):
                valid_tasks.append({
                    "contact_id": str(cid) if cid else "unknown",
                    "status": "validation_error",
                    "message": "contact_id должен быть непустой строкой",
                    "_early_error": True,
                })
            else:
                valid_tasks.append(cid)

        network_tasks = [t for t in valid_tasks if isinstance(t, str)]

        # --- Batch-логика прямо в sync-обёртке ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []

            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                tasks = [
                    self._delete_external_contact_single_async(session, cid, semaphore)
                    for cid in network_tasks
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for cid, res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            "contact_id": cid,
                            "status": "error",
                            "message": f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                        })
                    else:
                        final.append(res)
                return final

        # --- Запуск и защита от вложенного event loop ---
        try:
            net_results = asyncio.run(run_async())
        except RuntimeError as e:
            print(f"[DEL-EXT-CONTACTS] ✗ RuntimeError: {e}")
            return None if single_request else []
        except Exception as e:
            print(f"[DEL-EXT-CONTACTS] ✗ Неожиданная ошибка: {type(e).__name__}: {e}")
            return None if single_request else []

        # --- Собираем финальный список в исходном порядке ---
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get("_early_error"):
                item.pop("_early_error", None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    "contact_id": str(item),
                    "status": "error",
                    "message": "Нет результата выполнения",
                })

        # --- UX-логирование ---
        # Статусы, которые считаются успехом в вызывающем коде
        SUCCESS_STATUSES = {'success', 'success_retry', 'not_found'}

        if single_request:
            res = final_results[0] if final_results else {
                "contact_id": ids_to_process[0],
                "status": "error",
                "message": "Не удалось выполнить запрос",
            }
            tag = "[DEL-EXT-CONTACT]"
            if res["status"] in SUCCESS_STATUSES:
                print(f"{tag} ✓ Контакт {res['contact_id']}: {res['message']}")
            else:
                print(f"{tag} ✗ Контакт {res['contact_id']}: {res['message']}")
            return res

        # Пакетный режим
        success_count = sum(1 for r in final_results if r["status"] in SUCCESS_STATUSES)
        total_count = len(final_results)
        print(f"[DEL-EXT-CONTACTS-BATCH] ■ Итог: успешно={success_count}/{total_count}")
        for r in final_results:
            if r["status"] not in SUCCESS_STATUSES:
                print(f"  ✗ {r['contact_id']}: {r['message']}")

        return final_results


    async def _update_external_contact_single_async(
        self,
        session: aiohttp.ClientSession,
        contact_id: str,
        contact_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Асинхронное обновление данных внешнего контакта.
        Делегирует всю HTTP-логику универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param contact_id: ID контакта
        :param contact_data: Данные для обновления (firstName, lastName, title, company, department, address, externalId)
        :return: Словарь с результатом:
                 {
                     'id': str,
                     'success': bool,
                     'error': str | None,
                     'response_data': dict | str | None,
                     'message': str | None
                 }
        """
        url = f"{self.url}/external_contacts/{contact_id}"

        response = await self._make_api_request_async(
            session=session,
            method="PATCH",
            url=url,
            json_data=contact_data,
            operation_name=f"update_ext_contact({contact_id})",
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,        # jitter внутри, т.к. batch-обёртка им не управляет
            semaphore=None,     # семафором управляет batch-обёртка снаружи
        )

        # Минимальный маппинг под контракт вызывающего кода.
        # Все сообщения об ошибках уже сформированы в _make_api_request_async.
        return {
            'id': contact_id,
            'success': response['success'],
            'error': response['error'],
            'response_data': response['data'] if response['success'] else response['raw_text'],
            'message': (
                "Успешно после повтора"
                if response['success'] and response['retried']
                else "Контакт обновлён" if response['success']
                else None
            ),
        }

    def patch_external_contact_info(
        self,
        contact_ids: Union[str, List[str]],
        contact_data: Dict[str, Any]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Синхронная обёртка для обновления данных внешних контактов.
        Поддерживает один ID (str) или список ID (List[str]).
        Все указанные контакты обновляются одними и теми же данными.

        :param contact_ids: ID внешнего контакта (строка) или список ID.
        :param contact_data: Словарь с данными для обновления (firstName, lastName, title, company, department, address, externalId).
        :return: Словарь результата (если один ID) или список словарей (если список).

        Примеры:
            # Один контакт
            result = organization.patch_external_contact_info(
                "abc123",
                {"company": "Новая компания", "department": "IT"}
            )
            if result['success']:
                print(f"Контакт {result['id']} обновлён")
            else:
                print(f"Ошибка: {result['error']}")

            # Пакетное обновление (одни данные для всех)
            results = organization.patch_external_contact_info(
                ["abc123", "def456", "ghi789"],
                {"company": "Общая компания"}
            )
            success_count = sum(1 for r in results if r['success'])
            print(f"Успешно: {success_count} из {len(results)}")
        """
        # --- Определяем режим: одиночный или пакетный ---
        if isinstance(contact_ids, str):
            ids_to_process = [contact_ids]
            single_request = True
        elif isinstance(contact_ids, list):
            ids_to_process = list(contact_ids)
            single_request = False
        else:
            raise TypeError(
                f"Ожидается str или List[str], получено {type(contact_ids).__name__}"
            )

        if not ids_to_process:
            return None if single_request else []

        # --- Ранняя валидация ---
        if not contact_data or not isinstance(contact_data, dict):
            error_msg = "contact_data должен быть непустым словарём"
            print(f"[PATCH-EXT-CONTACTS] ✗ {error_msg}")
            if single_request:
                return {
                    'id': ids_to_process[0] if ids_to_process else 'unknown',
                    'success': False,
                    'error': error_msg,
                    'response_data': None,
                    'message': None,
                }
            return [
                {
                    'id': cid,
                    'success': False,
                    'error': error_msg,
                    'response_data': None,
                    'message': None,
                }
                for cid in ids_to_process
            ]

        # --- Предварительная валидация ID (early errors) ---
        valid_tasks = []
        for cid in ids_to_process:
            if not cid or not isinstance(cid, str):
                valid_tasks.append({
                    'id': str(cid) if cid else "unknown",
                    'success': False,
                    'error': "contact_id должен быть непустой строкой",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
            else:
                valid_tasks.append(cid)

        network_tasks = [t for t in valid_tasks if isinstance(t, str)]

        # --- Batch-логика прямо в sync-обёртке ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []

            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                async def bounded_update(contact_id: str):
                    async with semaphore:
                        await asyncio.sleep(random.uniform(0.01, 0.05))  # jitter
                        return await self._update_external_contact_single_async(
                            session, contact_id, contact_data
                        )

                tasks = [bounded_update(cid) for cid in network_tasks]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for cid, res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            'id': cid,
                            'success': False,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'response_data': None,
                            'message': None,
                        })
                    else:
                        final.append(res)
                return final

        # --- Запуск и защита от вложенного event loop ---
        try:
            net_results = asyncio.run(run_async())
        except RuntimeError as e:
            print(f"[PATCH-EXT-CONTACTS] ✗ RuntimeError: {e}")
            return None if single_request else []
        except Exception as e:
            print(f"[PATCH-EXT-CONTACTS] ✗ Неожиданная ошибка: {type(e).__name__}: {e}")
            return None if single_request else []

        # --- Собираем финальный список в исходном порядке ---
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get('_early_error'):
                item.pop('_early_error', None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    'id': str(item),
                    'success': False,
                    'error': 'Нет результата выполнения',
                    'response_data': None,
                    'message': None,
                })

        # --- UX-логирование ---
        if single_request:
            res = final_results[0] if final_results else {
                'id': ids_to_process[0],
                'success': False,
                'error': 'Не удалось выполнить запрос',
                'response_data': None,
                'message': None,
            }
            tag = "[PATCH-EXT-CONTACT]"
            if res['success']:
                print(f"{tag} ✓ Контакт {res['id']}: {res['message']}")
            else:
                print(f"{tag} ✗ Контакт {res['id']}: {res['error']}")
            return res

        # Пакетный режим
        success_count = sum(1 for r in final_results if r['success'])
        total_count = len(final_results)
        print(f"[PATCH-EXT-CONTACTS-BATCH] ■ Итог: успешно={success_count}/{total_count}")
        for r in final_results:
            if not r['success']:
                print(f"  ✗ {r['id']}: {r['error']}")

        return final_results

    def patch_external_contacts_batch_heterogeneous(
        self,
        tasks_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Публичный метод для массового обновления контактов с разными данными (гетерогенный batch).

        :param tasks_list: Список словарей вида:
            [
                {"id": "contact_1", "data": {"firstName": "Ivan"}},
                {"id": "contact_2", "data": {"lastName": "Petrov"}}
            ]
        :return: Список результатов для каждого контакта в том же порядке.

        Примеры:
            tasks = [
                {"id": "abc123", "data": {"company": "Компания А"}},
                {"id": "def456", "data": {"department": "IT", "title": "Developer"}},
                {"id": "ghi789", "data": {"address": "Москва"}},
            ]
            results = organization.patch_external_contacts_batch_heterogeneous(tasks)

            success_count = sum(1 for r in results if r['success'])
            print(f"Успешно: {success_count} из {len(results)}")
        """
        if not tasks_list:
            return []

        # --- Предварительная валидация структуры ---
        # Оставляем только валидные элементы: словарь с ключом 'id' (str) и 'data' (dict)
        valid_tasks = []
        for task in tasks_list:
            if not isinstance(task, dict):
                valid_tasks.append({
                    'id': 'unknown',
                    'success': False,
                    'error': f"Ожидается dict, получено {type(task).__name__}",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            cid = task.get('id')
            data = task.get('data')

            if not cid or not isinstance(cid, str):
                valid_tasks.append({
                    'id': str(cid) if cid else "unknown",
                    'success': False,
                    'error': "Поле 'id' должно быть непустой строкой",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            if not data or not isinstance(data, dict):
                valid_tasks.append({
                    'id': cid,
                    'success': False,
                    'error': "Поле 'data' должно быть непустым словарём",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            # Валидная задача
            valid_tasks.append({'id': cid, 'data': data})

        network_tasks = [t for t in valid_tasks if not (isinstance(t, dict) and t.get('_early_error'))]

        if not network_tasks:
            # Все задачи были невалидными
            for item in valid_tasks:
                item.pop('_early_error', None)
            print(f"[PATCH-EXT-CONTACTS-HETERO] ✗ Нет валидных задач для выполнения")
            return valid_tasks

        # --- Batch-логика прямо в sync-обёртке ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                async def bounded_update(task_item: Dict[str, Any]):
                    async with semaphore:
                        contact_id = task_item['id']
                        contact_data = task_item['data']
                        await asyncio.sleep(random.uniform(0.01, 0.05))  # jitter
                        return await self._update_external_contact_single_async(
                            session, contact_id, contact_data
                        )

                tasks = [bounded_update(task_item) for task_item in network_tasks]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for task_item, res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            'id': task_item['id'],
                            'success': False,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'response_data': None,
                            'message': None,
                        })
                    else:
                        final.append(res)
                return final

        # --- Запуск и защита от вложенного event loop ---
        try:
            net_results = asyncio.run(run_async())
        except RuntimeError as e:
            print(f"[PATCH-EXT-CONTACTS-HETERO] ✗ RuntimeError: {e}")
            return []
        except Exception as e:
            print(f"[PATCH-EXT-CONTACTS-HETERO] ✗ Неожиданная ошибка: {type(e).__name__}: {e}")
            return []

        # --- Собираем финальный список в исходном порядке ---
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get('_early_error'):
                item.pop('_early_error', None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    'id': item['id'],
                    'success': False,
                    'error': 'Нет результата выполнения',
                    'response_data': None,
                    'message': None,
                })

        # --- UX-логирование ---
        success_count = sum(1 for r in final_results if r['success'])
        total_count = len(final_results)
        print(f"[PATCH-EXT-CONTACTS-HETERO] ■ Итог: успешно={success_count}/{total_count}")
        for r in final_results:
            if not r['success']:
                print(f"  ✗ {r['id']}: {r['error']}")

        return final_results


    async def _patch_external_contact_emails_async(
        self,
        session: aiohttp.ClientSession,
        contact_id: str,
        emails_data: Union[List[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Асинхронное обновление электронных адресов внешнего контакта (полная замена, PUT).
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param contact_id: Идентификатор внешнего контакта
        :param emails_data: Либо список email-адресов, либо готовый dict с ключом 'emails'.
                            Каждый email: {"email": "...", "type": "...", "main": bool}
        :return: Словарь с результатом операции:
                 {
                     'id': str,
                     'success': bool,
                     'error': str | None,
                     'response_data': dict | str | None,
                     'message': str | None
                 }

        Примеры payload:
            # Вариант 1: список email-адресов (метод сам обернёт в {"emails": [...]})
            [
                {"email": "work@example.com", "type": "work", "main": True},
                {"email": "personal@example.com", "type": "personal", "main": False}
            ]

            # Вариант 2: готовый payload
            {
                "emails": [
                    {"email": "work@example.com", "type": "work", "main": True}
                ]
            }
        """
        url = f"{self.url}/external_contacts/{contact_id}/emails"
        op_name = f"patch_ext_emails({contact_id})"

        # --- Нормализация формата данных для API ---
        # API требует, чтобы корневой элемент был JSON-объектом, а не массивом.
        # Принимаем оба формата для гибкости.
        if isinstance(emails_data, list):
            payload = {"emails": emails_data}
        elif isinstance(emails_data, dict) and "emails" in emails_data:
            payload = emails_data
        else:
            return {
                'id': contact_id,
                'success': False,
                'error': (
                    f"Некорректный формат emails_data: ожидается list или dict с ключом 'emails', "
                    f"получено {type(emails_data).__name__}"
                ),
                'response_data': None,
                'message': None,
            }

        response = await self._make_api_request_async(
            session=session,
            method="PUT",
            url=url,
            json_data=payload,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,
            semaphore=None,  # семафором управляет batch-обёртка снаружи
        )

        # --- Минимальный маппинг под контракт вызывающего кода ---
        result = {
            'id': contact_id,
            'success': response['success'],
            'error': response['error'],
            'response_data': response['data'] if response['success'] else response['raw_text'],
            'message': None,
        }

        # Бизнес-специфика: человекочитаемое message при успехе
        if response['success']:
            base_msg = "Адреса успешно обновлены"
            if not response['data']:
                base_msg += " (пустой ответ)"
            if response['retried']:
                base_msg += " (после повтора)"
            result['message'] = base_msg

        return result

    def patch_external_contact_emails(
        self,
        contacts_data: Union[
            Tuple[str, Union[List[Dict[str, Any]], Dict[str, Any]]],
            List[Tuple[str, Union[List[Dict[str, Any]], Dict[str, Any]]]]
        ]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Синхронная обёртка для обновления электронных адресов внешних контактов.
        Поддерживает один контакт (кортеж) или список контактов (список кортежей).

        :param contacts_data:
            - Для одного контакта: кортеж (contact_id, emails_data),
              где emails_data — либо list[dict], либо dict с ключом 'emails'
            - Для списка контактов: список кортежей [(contact_id, emails_data), ...]
        :return: Словарь результата (если один контакт) или список словарей (если список).

        Примеры:
            # Один контакт
            result = organization.patch_external_contact_emails((
                "abc123",
                [
                    {"email": "work@example.com", "type": "work", "main": True},
                    {"email": "personal@example.com", "type": "personal", "main": False}
                ]
            ))
            if result['success']:
                print(f"Emails контакта {result['id']} обновлены")
            else:
                print(f"Ошибка: {result['error']}")

            # Пакетное обновление разных контактов
            results = organization.patch_external_contact_emails([
                ("abc123", [{"email": "new@example.com", "type": "work", "main": True}]),
                ("def456", {"emails": [{"email": "other@example.com", "type": "work", "main": True}]}),
                ("ghi789", "неверный формат"),  # early validation error
            ])

            success_count = sum(1 for r in results if r['success'])
            print(f"Успешно: {success_count} из {len(results)}")

            for r in results:
                if not r['success']:
                    print(f"  ✗ {r['id']}: {r['error']}")
        """
        # --- Определяем режим: одиночный или пакетный ---
        is_single = (
            isinstance(contacts_data, tuple)
            and len(contacts_data) == 2
            and isinstance(contacts_data[0], str)
        )

        if is_single:
            items = [contacts_data]
            single_request = True
        elif isinstance(contacts_data, list):
            items = list(contacts_data)
            single_request = False
        else:
            raise TypeError(
                "Ожидается кортеж (contact_id, emails_data) "
                "или список таких кортежей [(contact_id, emails_data), ...]"
            )

        if not items:
            return None if single_request else []

        # --- Предварительная валидация ---
        # Элементы будут либо кортежем (cid, emails), либо словарём-ошибкой валидации
        valid_tasks = []
        for item in items:
            if not isinstance(item, tuple) or len(item) != 2:
                valid_tasks.append({
                    'id': 'unknown',
                    'success': False,
                    'error': f"Ожидается кортеж (contact_id, emails_data), получено {type(item).__name__}",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            cid, emails = item

            if not cid or not isinstance(cid, str):
                valid_tasks.append({
                    'id': str(cid) if cid else "unknown",
                    'success': False,
                    'error': "contact_id должен быть непустой строкой",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            # Принимаем оба валидных формата: list или dict с ключом 'emails'
            if isinstance(emails, list) or (isinstance(emails, dict) and 'emails' in emails):
                valid_tasks.append((cid, emails))
            else:
                valid_tasks.append({
                    'id': cid,
                    'success': False,
                    'error': (
                        f"Данные emails должны быть списком (list) или dict с ключом 'emails', "
                        f"получено {type(emails).__name__}"
                    ),
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })

        network_tasks = [t for t in valid_tasks if isinstance(t, tuple)]

        # --- Batch-логика прямо в sync-обёртке ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []

            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                async def bounded_patch(cid, emails):
                    async with semaphore:
                        await asyncio.sleep(random.uniform(0.01, 0.05))  # jitter
                        return await self._patch_external_contact_emails_async(
                            session, cid, emails
                        )

                tasks = [bounded_patch(cid, emails) for cid, emails in network_tasks]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for (cid, _), res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            'id': cid,
                            'success': False,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'response_data': None,
                            'message': None,
                        })
                    else:
                        final.append(res)
                return final

        # --- Запуск и защита от вложенного event loop ---
        try:
            net_results = asyncio.run(run_async())
        except RuntimeError as e:
            print(f"[PATCH-EXT-EMAILS] ✗ RuntimeError: {e}")
            return None if single_request else []
        except Exception as e:
            print(f"[PATCH-EXT-EMAILS] ✗ Неожиданная ошибка: {type(e).__name__}: {e}")
            return None if single_request else []

        # --- Собираем финальный список в исходном порядке ---
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get('_early_error'):
                item.pop('_early_error', None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    'id': str(item[0]),
                    'success': False,
                    'error': 'Нет результата выполнения',
                    'response_data': None,
                    'message': None,
                })

        # --- UX-логирование ---
        if single_request:
            res = final_results[0] if final_results else {
                'id': items[0][0],
                'success': False,
                'error': 'Не удалось выполнить запрос',
                'response_data': None,
                'message': None,
            }
            tag = "[PATCH-EXT-EMAILS]"
            if res['success']:
                print(f"{tag} ✓ Контакт {res['id']}: {res['message']}")
            else:
                print(f"{tag} ✗ Контакт {res['id']}: {res['error']}")
            return res

        # Пакетный режим
        success_count = sum(1 for r in final_results if r['success'])
        total_count = len(final_results)
        print(f"[PATCH-EXT-EMAILS-BATCH] ■ Итог: успешно={success_count}/{total_count}")
        for r in final_results:
            if not r['success']:
                print(f"  ✗ {r['id']}: {r['error']}")

        return final_results


    async def _patch_external_contact_phones_async(
        self,
        session: aiohttp.ClientSession,
        contact_id: str,
        phones_data: Union[List[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Асинхронное обновление телефонных номеров внешнего контакта (полная замена, PUT).
        Делегирует HTTP-взаимодействие универсальной функции _make_api_request_async.

        :param session: Активный aiohttp.ClientSession
        :param contact_id: Идентификатор внешнего контакта
        :param phones_data: Либо список телефонов, либо готовый dict с ключом 'phones' вида {"phones": [...]}
        :return: Словарь с результатом операции:
                 {
                     'id': str,
                     'success': bool,
                     'error': str | None,
                     'response_data': dict | str | None,
                     'message': str | None
                 }

        Примеры payload:
            # Вариант 1: список телефонов (метод сам обернёт в {"phones": [...]})
            [
                {"phone": "+79001234567", "type": "mobile", "main": True},
                {"phone": "+74951234567", "type": "work", "main": False}
            ]

            # Вариант 2: готовый payload
            {
                "phones": [
                    {"phone": "+79001234567", "type": "mobile", "main": True}
                ]
            }
        """
        url = f"{self.url}/external_contacts/{contact_id}/phones"
        op_name = f"patch_ext_phones({contact_id})"

        # --- Нормализация формата данных для API ---
        # API требует, чтобы корневой элемент был JSON-объектом (message),
        # а не массивом. Принимаем оба формата для гибкости.
        if isinstance(phones_data, list):
            # Передан список телефонов — оборачиваем в требуемую структуру
            payload = {"phones": phones_data}
        elif isinstance(phones_data, dict) and "phones" in phones_data:
            # Данные уже в правильном формате — используем как есть
            payload = phones_data
        else:
            # Неожиданный формат данных — возвращаем ошибку валидации
            return {
                'id': contact_id,
                'success': False,
                'error': (
                    f"Некорректный формат phones_data: ожидается list или dict с ключом 'phones', "
                    f"получено {type(phones_data).__name__}"
                ),
                'response_data': None,
                'message': None,
            }

        response = await self._make_api_request_async(
            session=session,
            method="PUT",
            url=url,
            json_data=payload,
            operation_name=op_name,
            retry_on_500=True,
            max_retries=1,
            retry_delay=1.0,
            jitter=True,          # jitter внутри, т.к. batch-обёртка им не управляет
            semaphore=None,       # семафором управляет batch-обёртка снаружи
        )

        # --- Минимальный маппинг под контракт вызывающего кода ---
        result = {
            'id': contact_id,
            'success': response['success'],
            'error': response['error'],
            'response_data': response['data'] if response['success'] else response['raw_text'],
            'message': None,
        }

        # Бизнес-специфика: формируем человекочитаемое message при успехе
        if response['success']:
            base_msg = "Номера телефонов успешно обновлены"
            if not response['data']:
                base_msg += " (пустой ответ)"
            if response['retried']:
                base_msg += " (после повтора)"
            result['message'] = base_msg

        return result

    def patch_external_contact_phones(
        self,
        contacts_data: Union[
            Tuple[str, List[Dict[str, Any]]],
            List[Tuple[str, List[Dict[str, Any]]]]
        ]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Синхронная обёртка для обновления телефонных номеров внешних контактов.
        Поддерживает один контакт (кортеж) или список контактов (список кортежей).

        :param contacts_data:
            - Для одного контакта: кортеж (contact_id, list_of_phones)
            - Для списка контактов: список кортежей [(contact_id, list_of_phones), ...]
            
        Пример списка телефонов:
        [
            {"phone": "+79001234567", "type": "mobile", "main": True},
            {"phone": "+74951234567", "type": "work", "main": False}
        ]
        
        :return: Словарь результата (если один контакт) или список словарей (если список)

        Примеры:
            # Один контакт
            result = organization.patch_external_contact_phones((
                "abc123",
                [
                    {"phone": "+79001234567", "type": "mobile", "main": True},
                    {"phone": "+74951234567", "type": "work", "main": False}
                ]
            ))
            if result['success']:
                print(f"Телефоны контакта {result['id']} обновлены")
            else:
                print(f"Ошибка: {result['error']}")

            # Пакетное обновление разных контактов
            results = organization.patch_external_contact_phones([
                ("abc123", [{"phone": "+79001111111", "type": "mobile", "main": True}]),
                ("def456", [{"phone": "+79002222222", "type": "work", "main": True}]),
                ("ghi789", "неверный формат"),  # early validation error
            ])

            success_count = sum(1 for r in results if r['success'])
            print(f"Успешно: {success_count} из {len(results)}")

            for r in results:
                if not r['success']:
                    print(f"  ✗ {r['id']}: {r['error']}")
        """
        # --- Определяем режим: одиночный или пакетный ---
        is_single = (
            isinstance(contacts_data, tuple)
            and len(contacts_data) == 2
            and isinstance(contacts_data[0], str)
        )

        if is_single:
            items = [contacts_data]
            single_request = True
        elif isinstance(contacts_data, list):
            items = list(contacts_data)
            single_request = False
        else:
            raise TypeError(
                "Ожидается кортеж (contact_id, phones_data) "
                "или список таких кортежей [(contact_id, phones_data), ...]"
            )

        if not items:
            return None if single_request else []

        # --- Предварительная валидация ---
        valid_tasks = []
        for item in items:
            if not isinstance(item, tuple) or len(item) != 2:
                valid_tasks.append({
                    'id': 'unknown',
                    'success': False,
                    'error': f"Ожидается кортеж (contact_id, phones_data), получено {type(item).__name__}",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            cid, phones = item

            if not cid or not isinstance(cid, str):
                valid_tasks.append({
                    'id': str(cid) if cid else "unknown",
                    'success': False,
                    'error': "contact_id должен быть непустой строкой",
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })
                continue

            # Принимаем оба валидных формата: list или dict с ключом 'phones'
            if isinstance(phones, list):
                # Базовая проверка структуры элементов
                if phones and not all(isinstance(p, dict) for p in phones):
                    valid_tasks.append({
                        'id': cid,
                        'success': False,
                        'error': "Каждый телефон должен быть словарём (dict)",
                        'response_data': None,
                        'message': None,
                        '_early_error': True,
                    })
                    continue
                valid_tasks.append((cid, phones))
            elif isinstance(phones, dict) and 'phones' in phones:
                valid_tasks.append((cid, phones))
            else:
                valid_tasks.append({
                    'id': cid,
                    'success': False,
                    'error': (
                        f"phones_data должен быть списком (list) или dict с ключом 'phones', "
                        f"получено {type(phones).__name__}"
                    ),
                    'response_data': None,
                    'message': None,
                    '_early_error': True,
                })

        network_tasks = [t for t in valid_tasks if isinstance(t, tuple)]

        # --- Batch-логика прямо в sync-обёртке ---
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

        async def run_async():
            if not network_tasks:
                return []

            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            ) as session:
                semaphore = asyncio.Semaphore(API_RATE_LIMIT_SEMAPHORE)

                async def bounded_patch(cid, phones):
                    async with semaphore:
                        await asyncio.sleep(random.uniform(0.01, 0.05))  # jitter
                        return await self._patch_external_contact_phones_async(
                            session, cid, phones
                        )

                tasks = [bounded_patch(cid, phones) for cid, phones in network_tasks]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Обрабатываем результаты gather
                final = []
                for (cid, _), res in zip(network_tasks, results):
                    if isinstance(res, Exception):
                        final.append({
                            'id': cid,
                            'success': False,
                            'error': f"Критическая ошибка задачи: {type(res).__name__}: {res}",
                            'response_data': None,
                            'message': None,
                        })
                    else:
                        final.append(res)
                return final

        # --- Запуск и защита от вложенного event loop ---
        try:
            net_results = asyncio.run(run_async())
        except RuntimeError as e:
            print(f"[PATCH-EXT-PHONES] ✗ RuntimeError: {e}")
            return None if single_request else []
        except Exception as e:
            print(f"[PATCH-EXT-PHONES] ✗ Неожиданная ошибка: {type(e).__name__}: {e}")
            return None if single_request else []

        # --- Собираем финальный список в исходном порядке ---
        final_results = []
        net_iter = iter(net_results)
        for item in valid_tasks:
            if isinstance(item, dict) and item.get('_early_error'):
                item.pop('_early_error', None)
                final_results.append(item)
            else:
                res = next(net_iter, None)
                final_results.append(res if res else {
                    'id': str(item[0]),
                    'success': False,
                    'error': 'Нет результата выполнения',
                    'response_data': None,
                    'message': None,
                })

        # --- UX-логирование ---
        if single_request:
            res = final_results[0] if final_results else {
                'id': items[0][0],
                'success': False,
                'error': 'Не удалось выполнить запрос',
                'response_data': None,
                'message': None,
            }
            tag = "[PATCH-EXT-PHONES]"
            if res['success']:
                print(f"{tag} ✓ Контакт {res['id']}: {res['message']}")
            else:
                print(f"{tag} ✗ Контакт {res['id']}: {res['error']}")
            return res

        # Пакетный режим
        success_count = sum(1 for r in final_results if r['success'])
        total_count = len(final_results)
        print(f"[PATCH-EXT-PHONES-BATCH] ■ Итог: успешно={success_count}/{total_count}")
        for r in final_results:
            if not r['success']:
                print(f"  ✗ {r['id']}: {r['error']}")

        return final_results




def load_json_file(filename: str):
    with open(filename, "r") as input_file:
        try:
            return json.load(input_file)
        except json.decoder.JSONDecodeError:
            print("Wrong json file format")


def load_user_csv_list(filename):
    users_output = []
    with open(filename, "r", encoding='utf-8-sig') as input_file:
        reader = csv.DictReader(input_file, delimiter=';', quotechar='"')
        for row in reader:
            user_dict = {
                "departmentId": row.get('departmentId', 1),
                "name": {
                    "first": row.get('name', 'Name'),
                    "last": row.get('surname', 'Surname'),
                    "middle": row.get('middle', '')
                },
                "nickname": row.get('yandexmail_login', 'yandexmail_login'),
                "password": row.get('yandexmail_password', 'password'),
                "position": row.get('position', ''),
                "gender": row.get('gender', ''),
                "language": row.get('language', ''),
                "timezone": "Europe/Moscow",
            }
            users_output.append(user_dict)
    return users_output


def get_disk_report(organization):
    # Disk API:
    shared_users = organization.get_public_links()

    pprint(f"TOTAL USERS WITH SHARED FILES:"
           f"{shared_users}")
    ids = []
    for user_id in shared_users.keys():
        ids.append(user_id)

    shared_users_info = organization.get_all_users_info_by_id(ids)
    for detail_info in shared_users_info:
        shared_users[detail_info.get('email')] = shared_users.pop(detail_info.get('id'))

    output = [
        ['username',
         'type',
         'name',
         'publicUrl',
         'size',
         'createdAt'],
    ]
    total_users = 0

    for user, resources in shared_users.items():
        total_users += 1
        for resource in resources:
            per_user = []
            resource.pop('id')
            resource.pop('mimeType')
            resource.pop('modifiedAt')
            per_user.append(user)
            per_user.append(resource.get('type'))
            per_user.append(resource.get('name'))
            per_user.append(resource.get('publicUrl'))
            per_user.append(resource.get('size'))
            per_user.append(resource.get('createdAt'))
            output.append(per_user)

    output.append([f"TOTAL USERS WITH SHARE: {total_users}"])
    with open('disk_report.csv', 'w', encoding='utf-16') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=output[0])

        writer.writeheader()
        w = csv.writer(csvfile)
        w.writerows(output[1:])


def get_2fa_status_organization(organization):
    users = organization.get_all_users_id()
    users_info = organization.get_all_users_info_by_id(users)
    status_2fa = []
    for user in users:
        response = organization.get_user_2fa(user)
        if response.get('message') != 'Internal error':
            status_2fa.append(organization.get_user_2fa(user))
    for user_info in users_info:
        for user_2fa in status_2fa:
            if user_2fa.get('userId') == user_info.get('id'):
                pass
    return status_2fa


if __name__ == "__main__":
    # Get tokens for the organization access:
    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path)

    organization = API360(os.environ.get('orgId'), os.environ.get('access_token'))

    print(organization.get_all_users())
