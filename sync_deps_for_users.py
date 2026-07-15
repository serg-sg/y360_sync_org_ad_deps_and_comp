#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт синхронизации иерархии подразделений Active Directory с Яндекс 360.

Версия 1.2 (Финальные исправления):
1. Исключение роботов (isRobot: true) из логики перемещения отсутствующих пользователей.
2. Автоматическое создание/поиск подразделения "Заблокированные" (parentId=1) для отключенных пользователей.
3. Очистка поля description, если оно полностью совпадает с name.
4. Строгая привязка иерархии по externalId (GUID). Защита от "захвата" подразделений с одинаковым 
   именем, но находящихся в других ветках AD (разный msDS-parentdistname).
"""

import os
import sys
import ssl
import logging
import logging.handlers as handlers
from typing import Optional, Dict, List, Set, Tuple, Any
from dotenv import load_dotenv
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, set_config_parameter, ServerPool, ROUND_ROBIN
from ldap3.core.exceptions import LDAPBindError, LDAPAttributeError
from lib.y360_api.api_script import API360
import concurrent.futures

# ============================================================================
# КОНСТАНТЫ И НАСТРОЙКИ
# ============================================================================

LOG_FILE = "sync_deps.log"
LDAP_PAGE_SIZE = 1000

# Маппинг по умолчанию
DEFAULT_DEPARTMENT_NAME = 'description,name'
DEFAULT_DEPARTMENT_DESCRIPTION = 'description'
DEFAULT_DEPARTMENT_EXTERNALID = 'objectGUID'
DEFAULT_DEPARTMENT_PARENT = 'msDS-parentdistname'

DEFAULT_LDAP_USER_SEARCH_FILTER = (
    '(&(objectClass=user)(objectCategory=person)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
)
DEFAULT_LDAP_DEPARTMENT_SEARCH_FILTER = '(objectClass=organizationalUnit)'
DEFAULT_ATTRIB_USER_LIST = 'distinguishedName,mail,displayName,company,department,objectGUID,msDS-parentdistname'

logger = logging.getLogger("sync_deps")
logger.setLevel(logging.DEBUG)

# ============================================================================
# ЛОГИРОВАНИЕ
# ============================================================================

def setup_logging():
    """Настройка хендлеров логов."""
    if logger.hasHandlers():
        logger.handlers.clear()
    
    fmt = logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)
    
    file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=20, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.info("Логирование инициализировано")

# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

def parse_env_list(env_value: str, default_value: Optional[List[str]] = None) -> List[str]:
    """Парсит строку из .env в список."""
    if not env_value or not env_value.strip():
        return default_value if isinstance(default_value, list) else (default_value.split(',') if default_value else [])
    return [item.strip() for item in env_value.split(',') if item.strip()]

def get_safe_val(entry: Any, attr_name: str, default: str = "") -> str:
    """Безопасное получение значения атрибута из ldap3.Entry."""
    try:
        if attr_name not in entry: return default
        val_obj = entry[attr_name]
        if val_obj.value is None: return default
        
        raw_val = val_obj.value
        if isinstance(raw_val, list):
            raw_val = raw_val[0] if raw_val else None
        if raw_val is None: return default
        
        if isinstance(raw_val, bytes):
            return raw_val.hex().strip('{}').lower()
            
        res = str(raw_val).strip()
        return res[1:-1].lower() if res.startswith('{') and res.endswith('}') else res
    except Exception:
        return default

def normalize_dn(dn: str) -> str:
    """Нормализует DN для сравнения (нижний регистр, без лишних пробелов)."""
    if not dn: return ""
    return dn.strip().lower().replace(' = ', '=').replace(' , ', ',')

def get_parent_dn(dn: str) -> Optional[str]:
    """Возвращает родительский DN."""
    if not dn or ',' not in dn: return None
    parts = dn.split(',', 1)
    return parts[1].strip() if len(parts) > 1 else None

def get_name_from_raw_dn(dn: str) -> str:
    """Извлекает имя (CN или OU) из полного DN, сохраняя регистр."""
    if not dn: return ""
    try:
        first_part = dn.split(',')[0]
        if '=' in first_part:
            return first_part.split('=', 1)[1].strip()
    except Exception:
        pass
    return ""

def get_fallback_value(entry: Any, attr_names: List[str], default: str = "") -> str:
    """Возвращает первое непустое значение из списка атрибутов."""
    for attr in attr_names:
        val = get_safe_val(entry, attr, "").strip()
        if val: return val
    return default

def build_y360_users_map(y360_users_list: List[Dict]) -> Dict[str, Dict]:
    """
    Строит расширенный маппинг email -> пользователь для Яндекс 360.
    
    Учитывает:
    1. Основной email (поле 'email')
    2. Алиасы (поле 'aliases')
    3. Email-контакты (поле 'contacts' с type='email')
    
    Это позволяет находить пользователя в Я360 по любому из его адресов,
    даже если в AD указан не основной email, а алиас или старый адрес.
    
    :param y360_users_list: Список пользователей из API Я360
    :return: Словарь {email_lower: user_data}
    """
    y360_users_map = {}
    collision_count = 0
    
    for u in y360_users_list:
        user_emails = set()
        
        # 1. Основной email
        main_email = u.get('email', '').lower().strip()
        if main_email:
            user_emails.add(main_email)
        
        # 2. Алиасы
        for alias in u.get('aliases', []):
            alias_lower = alias.lower().strip()
            if alias_lower:
                user_emails.add(alias_lower)
        
        # 3. Email-контакты (включая синтетические и ручные)
        for contact in u.get('contacts', []):
            if contact.get('type') == 'email':
                contact_email = contact.get('value', '').lower().strip()
                if contact_email:
                    user_emails.add(contact_email)
        
        # Заполняем маппинг
        for email in user_emails:
            if email in y360_users_map:
                # Коллизия: один email у двух разных пользователей
                existing = y360_users_map[email]
                collision_count += 1
                logger.warning(
                    f"⚠ Коллизия email '{email}': "
                    f"принадлежит пользователю ID={existing.get('id')} ({existing.get('email')}) "
                    f"и ID={u.get('id')} ({u.get('email')}). "
                    f"Будет использован первый найденный."
                )
            else:
                y360_users_map[email] = u
    
    logger.info(
        f"Построен расширенный маппинг пользователей Я360: "
        f"{len(y360_users_map)} уникальных email-адресов для {len(y360_users_list)} пользователей. "
        f"Коллизий: {collision_count}."
    )
    
    return y360_users_map

# ============================================================================
# ЗАГРУЗКА ДАННЫХ ИЗ AD
# ============================================================================

def _get_ldap_connection():
    """Создает и возвращает соединение с LDAP."""
    ldap_host_env = os.environ.get('LDAP_HOST', '')
    ldap_hosts = [h.strip() for h in ldap_host_env.split(',') if h.strip()]
    if not ldap_hosts:
        logger.error("LDAP_HOST не задан!"); sys.exit(1)
        
    ldap_port = int(os.environ.get('LDAP_PORT', 636))
    ldap_user = os.environ.get('LDAP_USER')
    ldap_password = os.environ.get('LDAP_PASSWORD')
    
    use_ssl = os.environ.get('LDAP_USE_SSL', 'False').lower() in ['true', '1', 'yes']
    validate_cert = os.environ.get('LDAP_VALIDATE_CERT', 'True').lower() in ['true', '1', 'yes']
    
    tls_config = None
    if use_ssl:
        ca_path = os.environ.get('CA_ROOT_PATH')
        if validate_cert and ca_path and os.path.exists(ca_path):
            tls_config = Tls(ca_certs_file=ca_path, validate=ssl.CERT_REQUIRED)
            if hasattr(tls_config, 'ssl_context') and tls_config.ssl_context:
                tls_config.ssl_context.check_hostname = False
        else:
            tls_config = Tls(validate=ssl.CERT_NONE)
            
    server_list = [Server(h, port=ldap_port, use_ssl=use_ssl, tls=tls_config, get_info=ALL) for h in ldap_hosts]
    pool = ServerPool(server_list, ROUND_ROBIN, active=True, exhaust=True)
    
    try:
        conn = Connection(pool, user=ldap_user, password=ldap_password, receive_timeout=30)
        if not conn.bind():
            logger.error(f"LDAP Bind failed: {conn.result}"); sys.exit(1)
        return conn
    except Exception as e:
        logger.error(f"Ошибка подключения: {e}"); sys.exit(1)

def get_ldap_departments() -> List[Dict[str, Any]]:
    """Загружает подразделения из AD."""
    conn = _get_ldap_connection()
    base_dn = os.environ.get('LDAP_BASE_DN')
    search_filter = os.environ.get('LDAP_DEPARTMENT_SEARCH_FILTER', DEFAULT_LDAP_DEPARTMENT_SEARCH_FILTER)
    
    attrs = set(['distinguishedName'])
    for k in ['DEPARTMENT_NAME', 'DEPARTMENT_DESCRIPTION', 'DEPARTMENT_EXTERNALID', 'DEPARTMENT_PARENT']:
        attrs.update(parse_env_list(os.environ.get(k, '')))
    
    results = []
    cookie = None
    try:
        while True:
            conn.search(base_dn, search_filter, search_scope=SUBTREE, attributes=list(attrs), paged_size=LDAP_PAGE_SIZE, paged_cookie=cookie)
            if conn.last_error: break
            results.extend(conn.entries)
            cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
            if not cookie: break
    finally:
        conn.unbind()
        
    deps = []
    name_attrs = parse_env_list(os.environ.get('DEPARTMENT_NAME', DEFAULT_DEPARTMENT_NAME))
    desc_attrs = parse_env_list(os.environ.get('DEPARTMENT_DESCRIPTION', DEFAULT_DEPARTMENT_DESCRIPTION))
    extid_attrs = parse_env_list(os.environ.get('DEPARTMENT_EXTERNALID', DEFAULT_DEPARTMENT_EXTERNALID))
    parent_attrs = parse_env_list(os.environ.get('DEPARTMENT_PARENT', DEFAULT_DEPARTMENT_PARENT))
    
    for item in results:
        dn = get_safe_val(item, 'distinguishedName')
        if not dn: continue
        
        ext_id = get_fallback_value(item, extid_attrs, '').lower().strip('{}')
        parent_dn = get_fallback_value(item, parent_attrs, '')
        
        deps.append({
            'dn': dn,
            'dn_normalized': normalize_dn(dn),
            'name': get_fallback_value(item, name_attrs, '').strip(),
            'description': get_fallback_value(item, desc_attrs, '').strip(),
            'external_id': ext_id if ext_id else normalize_dn(dn),
            'parent_dn': parent_dn,
            'parent_dn_normalized': normalize_dn(parent_dn)
        })
    return deps

def get_ldap_users() -> Dict[str, Dict[str, Any]]:
    """Загружает пользователей из AD."""
    conn = _get_ldap_connection()
    base_dn = os.environ.get('LDAP_BASE_DN')
    search_filter = os.environ.get('LDAP_USER_SEARCH_FILTER', DEFAULT_LDAP_USER_SEARCH_FILTER)
    attrs = parse_env_list(os.environ.get('ATTRIB_USER_LIST', DEFAULT_ATTRIB_USER_LIST))

    # ГАРАНТИРОВАННО добавляем критически важные атрибуты, даже если их нет в .env
    # ДОБАВЛЕНО: proxyAddresses для сбора всех алиасов и старых email-адресов
    mandatory_user_attrs = ['distinguishedName', 'mail', 'msDS-parentdistname', 'proxyAddresses']
    for attr in mandatory_user_attrs:
        if attr not in attrs:
            attrs.append(attr)
            logger.debug(f"Принудительно добавлен обязательный атрибут пользователя: {attr}")

    results = []
    cookie = None
    try:
        while True:
            conn.search(base_dn, search_filter, search_scope=SUBTREE, attributes=attrs, paged_size=LDAP_PAGE_SIZE, paged_cookie=cookie)
            if conn.last_error: break
            results.extend(conn.entries)
            cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
            if not cookie: break
    finally:
        conn.unbind()
        
    users = {}
    for item in results:
        mail = get_safe_val(item, 'mail', '').lower().strip()
        if not mail or '@' not in mail: continue
        
        # Базовые данные пользователя
        user_data = {
            'dn': get_safe_val(item, 'distinguishedName'),
            'dn_normalized': normalize_dn(get_safe_val(item, 'distinguishedName')),
            'parent_dn': get_safe_val(item, 'msDS-parentdistname'),
            'parent_dn_normalized': normalize_dn(get_safe_val(item, 'msDS-parentdistname'))
        }

        # --- Обработка proxyAddresses (многозначный атрибут) ---
        try:
            # В ldap3 для получения всех значений многозначного атрибута используется .values
            proxy_addresses_raw = item['proxyAddresses'].values 
            
            if proxy_addresses_raw:
                additional_emails = []
                for addr in proxy_addresses_raw:
                    addr_str = str(addr).strip()
                    # Формат в AD обычно 'SMTP:user@domain.com' или 'smtp:user@domain.com'
                    if ':' in addr_str:
                        email_part = addr_str.split(':', 1)[1].lower()
                        if email_part:
                            additional_emails.append(email_part)
                
                # Добавляем в словарь ТОЛЬКО если нашли хотя бы один адрес
                if additional_emails:
                    user_data['additional_emails'] = additional_emails
                    
        except (KeyError, AttributeError, TypeError):
            # Если атрибут отсутствует в AD или произошел сбой парсинга — просто пропускаем
            pass

        users[mail] = user_data

    return users

# ============================================================================
# ЛОГИКА ИЕРАРХИИ И ФИЛЬТРАЦИИ
# ============================================================================

def build_active_departments_tree(ad_departments: List[Dict], ad_users: Dict, root_dn: str) -> List[Dict]:
    """Фильтрует подразделения: оставляет только те, где есть пользователи, и их предков."""
    if not ad_departments: return []
    dep_index = {d['dn_normalized']: d for d in ad_departments}
    active_dns = set()
    
    users_with_parent = 0
    users_without_parent = 0
    users_parent_not_in_index = 0

    for mail, u in ad_users.items():
        p_dn = u.get('parent_dn_normalized', '')
        if p_dn:
            users_with_parent += 1
            if p_dn in dep_index:
                active_dns.add(p_dn)
            else:
                users_parent_not_in_index += 1
                if users_parent_not_in_index <= 5:
                    logger.debug(f"Пользователь {mail}: parent_dn '{p_dn}' не найден в списке OU")
        else:
            users_without_parent += 1

    logger.info(f"Статистика пользователей AD: всего={len(ad_users)}, "
                f"с parent_dn={users_with_parent}, без parent_dn={users_without_parent}, "
                f"parent_dn не в списке OU={users_parent_not_in_index}")
    logger.info(f"Найдено уникальных родительских OU пользователей: {len(active_dns)}")
            
    if root_dn and root_dn in dep_index:
        active_dns.add(root_dn)
        
    changed = True
    while changed:
        changed = False
        current_dns = list(active_dns)
        for dn in current_dns:
            parent = get_parent_dn(dn)
            if parent:
                p_norm = normalize_dn(parent)
                if p_norm in dep_index and p_norm not in active_dns:
                    active_dns.add(p_norm)
                    changed = True
                if p_norm == root_dn:
                    active_dns.add(root_dn)
                    
    return [d for d in ad_departments if d['dn_normalized'] in active_dns]

def topological_sort(departments: List[Dict]) -> List[Dict]:
    """Сортирует подразделения так, чтобы родители шли перед детьми."""
    if not departments: return []
    dep_index = {d['dn_normalized']: d for d in departments}
    for d in departments: d['children'] = []
    roots = []
    
    for d in departments:
        p = d['parent_dn_normalized']
        if p and p in dep_index:
            dep_index[p]['children'].append(d)
        else:
            roots.append(d)
            
    sorted_list = []
    def _dfs(node):
        sorted_list.append(node)
        for child in node.get('children', []): _dfs(child)
    for r in roots: _dfs(r)
    return sorted_list

# ============================================================================
# СИНХРОНИЗАЦИЯ С ЯНДЕКС 360
# ============================================================================

def ensure_blocked_department(organization: API360, dry_run: bool) -> str:
    """Гарантирует существование подразделения 'Заблокированные' в корне (parentId=1)."""
    blocked_name = "Заблокированные"
    try:
        deps = organization.get_departments_list()
        for d in deps:
            if d.get('name') == blocked_name and d.get('parentId') == 1:
                return str(d['id'])
        
        logger.info(f"Подразделение '{blocked_name}' не найдено. Создание...")
        if not dry_run:
            success, msg = organization.post_create_department({
                'name': blocked_name,
                'parentId': 1
            })
            if success:
                deps = organization.get_departments_list()
                for d in deps:
                    if d.get('name') == blocked_name and d.get('parentId') == 1:
                        logger.info(f"✓ Подразделение '{blocked_name}' создано (ID: {d['id']})")
                        return str(d['id'])
            else:
                logger.error(f"✗ Ошибка создания '{blocked_name}': {msg}")
        else:
            logger.info(f"[DRY_RUN] Будет создано подразделение '{blocked_name}' (parentId=1)")
            return "blocked_dry_run_id"
            
    except Exception as e:
        logger.error(f"Ошибка при проверке/создании '{blocked_name}': {e}")
    
    return "1" # Fallback на корень в случае критической ошибки

def sync_departments_hierarchy(
    organization: API360,
    ad_departments: List[Dict], 
    root_dn: str, 
    dry_run: bool
) -> Dict[str, str]:
    """Синхронизирует структуру подразделений в Яндекс 360 со строгой привязкой по externalId."""
    logger.info("Получение списка подразделений Яндекс 360...")
    y360_list = organization.get_departments_list()
    
    y360_by_extid = {d.get('externalId', '').lower(): d for d in y360_list if d.get('externalId')}
    y360_by_name_parent = {}
    for d in y360_list:
        key = (d.get('name', '').lower(), d.get('parentId'))
        if key not in y360_by_name_parent or (d.get('externalId') and not y360_by_name_parent[key].get('externalId')):
            y360_by_name_parent[key] = d
            
    ad_to_y360_id = {}
    sorted_deps = topological_sort(ad_departments)
    
    # Списки для пакетных операций
    batch_updates = []       # [(y360_id, update_data, ad_name_clean, existing_ref), ...]
    batch_creates = []       # [(create_payload, ad_dn, target_name, target_parent_id), ...]
    
    for ad_dep in sorted_deps:
        ad_dn = ad_dep['dn_normalized']
        ad_name = ad_dep['name'] or get_name_from_raw_dn(ad_dep['dn'])
        ad_desc_raw = ad_dep['description']
        ad_ext_id = ad_dep['external_id']
        ad_parent_dn = ad_dep['parent_dn_normalized']
        
        is_root = (ad_dn == root_dn)
        raw_parent_id = ad_to_y360_id.get(ad_parent_dn, 1) if not is_root else 1
        try:
            target_parent_id = int(raw_parent_id)
        except (ValueError, TypeError):
            target_parent_id = 1

        target_name = (ad_name or "").strip()
        target_desc = (ad_desc_raw or "").strip()
        if target_desc and target_name and target_desc.lower() == target_name.lower():
            target_desc = ""

        existing = y360_by_extid.get(ad_ext_id) if ad_ext_id else None
        if not existing:
            search_key = (target_name.lower(), target_parent_id)
            existing = y360_by_name_parent.get(search_key)
            if existing and existing.get('parentId') != target_parent_id:
                if existing.get('externalId'):
                    existing = None

        if existing:
            y360_id = existing.get('id')
            update_data = {}
            needs_update = False
            
            if ad_ext_id and not existing.get('externalId'):
                update_data['externalId'] = ad_ext_id
                needs_update = True
                
            existing_parent_id = existing.get('parentId')
            try:
                existing_parent_id = int(existing_parent_id) if existing_parent_id is not None else 1
            except (ValueError, TypeError):
                existing_parent_id = 1
            if existing_parent_id != target_parent_id:
                update_data['parentId'] = target_parent_id
                needs_update = True
                
            ad_name_clean = target_name
            existing_name_clean = (existing.get('name') or "").strip()
            if not is_root:
                if existing_name_clean != ad_name_clean:
                    update_data['name'] = ad_name_clean
                    needs_update = True
            else:
                if target_desc and existing_name_clean != ad_name_clean:
                    update_data['name'] = ad_name_clean
                    needs_update = True
                elif not target_desc:
                    logger.debug(f"Корень '{ad_name_clean}' без description в AD, имя в Я360 не меняется.")

            existing_desc = (existing.get('description') or "").strip()
            if existing_desc != target_desc:
                update_data['description'] = target_desc
                needs_update = True

            if needs_update:
                if not dry_run:
                    # Собираем в пакет вместо немедленного вызова
                    batch_updates.append((y360_id, update_data, ad_name_clean, existing))
                else:
                    logger.info(f"[DRY_RUN] Обновление: {ad_name_clean} -> {update_data}")
                    existing.update(update_data)
                    
            ad_to_y360_id[ad_dn] = y360_id
            
        else:
            if is_root and not target_desc:
                logger.info(f"Корневое подразделение '{target_name}' без description. Используем ID=1.")
                ad_to_y360_id[ad_dn] = '1'
                continue
                
            create_payload = {
                'name': target_name,
                'parentId': target_parent_id,
                'externalId': ad_ext_id
            }
            if target_desc: 
                create_payload['description'] = target_desc
            
            if not dry_run:
                # Собираем в пакет созданий
                batch_creates.append((create_payload, ad_dn, target_name, target_parent_id))
            else:
                logger.info(f"[DRY_RUN] Создание: {target_name} (parentId: {target_parent_id})")
                ad_to_y360_id[ad_dn] = 'dry_run'

    # === ПАКЕТНОЕ ВЫПОЛНЕНИЕ ОБНОВЛЕНИЙ (ПАРАЛЛЕЛЬНО) ===
    if batch_updates:
        logger.info(f"Пакетное обновление подразделений: {len(batch_updates)} задач...")
        
        def do_patch(item):
            y360_id, update_data, ad_name_clean, existing_ref = item
            try:
                res = organization.patch_department_info(y360_id, update_data)
                if res:
                    existing_ref.update(update_data)
                    return (ad_name_clean, True)
                return (ad_name_clean, False)
            except Exception as e:
                logger.error(f"✗ Ошибка обновления {ad_name_clean}: {e}")
                return (ad_name_clean, False)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(do_patch, batch_updates))
        
        success = sum(1 for _, ok in results if ok)
        logger.info(f"✓ Обновлено подразделений: {success}/{len(batch_updates)}")

    # === ПОСЛЕДОВАТЕЛЬНОЕ СОЗДАНИЕ (с сохранением иерархии) ===
    # Создаём по порядку topological_sort, чтобы родитель создался раньше ребёнка
    if batch_creates:
        logger.info(f"Создание подразделений: {len(batch_creates)} задач...")
        for create_payload, ad_dn, target_name, target_parent_id in batch_creates:
            # Проверяем, что родитель уже создан (его ID должен быть в ad_to_y360_id)
            actual_parent_id = ad_to_y360_id.get(create_payload.get('_parent_dn', ''), target_parent_id)
            create_payload['parentId'] = actual_parent_id
            
            logger.info(f"Создание: {target_name} (parentId: {actual_parent_id})")
            success, msg = organization.post_create_department(create_payload)
            if success:
                logger.info(f"✓ Создано: {target_name}")
                if create_payload.get('externalId'):
                    dep_info = organization.get_department_info_by_external_id(create_payload['externalId'])
                    if dep_info and dep_info.get('success'):
                        new_id = dep_info.get('id')
                        ad_to_y360_id[ad_dn] = new_id
                        new_dep_data = {**create_payload, 'id': new_id, 'parentId': actual_parent_id}
                        y360_by_extid[create_payload['externalId'].lower()] = new_dep_data
                        y360_by_name_parent[(target_name.lower(), actual_parent_id)] = new_dep_data
                    else:
                        logger.warning(f"Не удалось получить ID созданного {target_name}.")
                        ad_to_y360_id[ad_dn] = 'unknown'
            else:
                logger.error(f"✗ Ошибка создания {target_name}: {msg}")
                ad_to_y360_id[ad_dn] = 'unknown'

    return ad_to_y360_id

def assign_users_to_departments(
    organization: API360,
    ad_users: Dict[str, Dict],
    ad_to_y360_id: Dict[str, str],
    all_ad_deps: List[Dict],
    root_dn: str,
    dry_run: bool
):
    """Назначает пользователей из AD в подразделения на основе msDS-parentdistname (пакетный режим)."""
    logger.info("Загрузка пользователей Яндекс 360 для назначения...")
    try:
        y360_users_list = organization.get_all_users()
        # === Расширенное сопоставление по всем email-адресам ===
        y360_users_map = build_y360_users_map(y360_users_list)
    except Exception as e:
        logger.error(f"Ошибка получения пользователей Я360: {e}")
        return
    
    # === ОТЛАДКА 1: Проверка сопоставления подразделений ===
    suspicious_deps = {dn: dep_id for dn, dep_id in ad_to_y360_id.items() 
                       if (not str(dep_id).isdigit() or str(dep_id) == '1') and dn != root_dn}
    if suspicious_deps:
        logger.warning(f"⚠ Подозрительные сопоставления подразделений (не число или ID=1): {suspicious_deps}")
    else:
        logger.debug("Все подразделения сопоставлены на корректные числовые ID.")
    
    all_ad_deps_dns = {d['dn_normalized'] for d in all_ad_deps}
    
    batch_updates = []
    skipped_count = 0
    users_in_root_y360 = [] 
    
    for email, u_data in ad_users.items():
        # === НОВОЕ: Поиск пользователя в Я360 с учётом дополнительных email из proxyAddresses ===
        y360_user = y360_users_map.get(email)
        matched_email = email  # По какому email нашли
        
        if not y360_user:
            # Если по основному email не нашли, ищем по дополнительным (алиасам из proxyAddresses)
            additional_emails = u_data.get('additional_emails', [])
            for add_email in additional_emails:
                y360_user = y360_users_map.get(add_email)
                if y360_user:
                    matched_email = add_email
                    logger.debug(f"Пользователь {email} найден в Я360 по дополнительному email: {add_email}")
                    break
        
        if not y360_user: 
            continue
        
        parent_dn = u_data.get('parent_dn_normalized', '')
        target_dept_id = None
        fallback_path = []
        
        if parent_dn and parent_dn in ad_to_y360_id:
            target_dept_id = ad_to_y360_id[parent_dn]
        else:
            curr = parent_dn
            while curr:
                fallback_path.append(curr)
                if curr in ad_to_y360_id:
                    target_dept_id = ad_to_y360_id[curr]
                    break
                curr = normalize_dn(get_parent_dn(curr))
                if curr == root_dn and root_dn in ad_to_y360_id:
                    target_dept_id = ad_to_y360_id[root_dn]
                    break
        
        if not target_dept_id or target_dept_id in ['unknown', 'dry_run']:
            logger.warning(
                f"⚠ КРИТИЧНО: Пользователь {email} (найден по {matched_email}) отправляется в корень (ID=1)! "
                f"Причина: target_dept_id='{target_dept_id}'. "
                f"msDS-parentdistname из AD: '{parent_dn}'. "
                f"Путь fallback: {' -> '.join(fallback_path) if fallback_path else 'пусто'}."
            )
            if parent_dn and parent_dn not in all_ad_deps_dns:
                logger.warning(f"  ↳ Атрибут msDS-parentdistname '{parent_dn}' отсутствует в общем списке OU из AD!")
            target_dept_id = '1'
            
        current_dept = str(y360_user.get('departmentId', '1'))
        
        if str(target_dept_id) == '1':
            logger.info(
                f"🔍 Отладка пользователя {email} (найден по {matched_email}): "
                f"Текущее подразделение в Я360: {current_dept}. "
                f"Атрибут msDS-parentdistname из AD: '{parent_dn}'. "
                f"Путь обхода (fallback): {' -> '.join(fallback_path) if fallback_path else 'прямое совпадение с корнем'}."
            )
        
        if current_dept == '1':
            users_in_root_y360.append({
                'email': email,
                'matched_by': matched_email,
                'parent_dn': parent_dn,
                'target_dept_id': str(target_dept_id),
                'fallback': ' -> '.join(fallback_path) if fallback_path else 'прямое совпадение'
            })

        if current_dept == str(target_dept_id):
            skipped_count += 1
            continue
        
        if not dry_run:
            batch_updates.append((y360_user['id'], {'departmentId': int(target_dept_id)}))
            logger.debug(f"В пакет: {email} (matched: {matched_email}) {current_dept} -> {target_dept_id}")
        else:
            logger.info(f"[DRY_RUN] {email} (matched: {matched_email}): {current_dept} -> {target_dept_id}")
    
    if users_in_root_y360:
        logger.warning(f"🔍 Пользователи, находящиеся в корне Я360 (всего {len(users_in_root_y360)}):")
        for u in users_in_root_y360[:20]:
            logger.warning(
                f"  👤 {u['email']} (найден по {u['matched_by']}): "
                f"parent_dn='{u['parent_dn']}', "
                f"target_dept_id='{u['target_dept_id']}', "
                f"path={u['fallback']}"
            )
    
    if batch_updates:
        logger.info(f"Назначение пользователей: отправляем пакет из {len(batch_updates)} обновлений...")
        if not dry_run:
            try:
                results = organization.patch_user_info(batch_updates)
                success_count = sum(1 for r in results if r is not None)
                error_count = len(results) - success_count
                logger.info(f"✓ Назначение завершено: успешно={success_count}, ошибок={error_count}, пропущено (без изменений)={skipped_count}")
            except Exception as e:
                logger.error(f"✗ Критическая ошибка пакетного назначения: {e}")
        else:
            logger.info(f"[DRY_RUN] Планируется назначение {len(batch_updates)} пользователей.")
    else:
        logger.info(f"Назначение завершено: все пользователи уже в целевых подразделениях (пропущено={skipped_count}).")


def reset_dismissed_users_to_root(organization: API360, ad_users: Dict[str, Dict], dry_run: bool):
    """
    Перемещает пользователей Я360, отсутствующих в AD (пакетный режим):
    - Заблокированных (isEnabled: false) -> в "Заблокированные"
    - Активных (isEnabled: true) -> в корень (id=1)
    - Игнорирует роботов (isRobot: true)
    """
    logger.info("Проверка пользователей Я360, отсутствующих в текущей выгрузке AD...")
    try:
        y360_users_list = organization.get_all_users()
        y360_users_map = build_y360_users_map(y360_users_list)
    except Exception as e:
        logger.error(f"Ошибка получения пользователей Я360: {e}")
        return

    blocked_dept_id = ensure_blocked_department(organization, dry_run)
    logger.info(f"Целевое подразделение для заблокированных: ID={blocked_dept_id}")

    # === НОВОЕ: Расширенное множество email из AD с учётом proxyAddresses ===
    ad_emails = set()
    additional_emails_count = 0
    for email, u_data in ad_users.items():
        ad_emails.add(email.lower())
        # Добавляем все дополнительные email из proxyAddresses
        for add_email in u_data.get('additional_emails', []):
            ad_emails.add(add_email.lower())
            additional_emails_count += 1
    
    logger.info(f"Собрано email-адресов из AD: основных={len(ad_users)}, "
                f"дополнительных (алиасов)={additional_emails_count}, "
                f"всего уникальных={len(ad_emails)}")

    batch_updates = []
    moved_count = 0
    skipped_robots = 0

    for y360_user in y360_users_list:
        # Собираем все email пользователя Я360
        y360_emails = set()
        
        main_email = y360_user.get('email', '').lower().strip()
        if main_email:
            y360_emails.add(main_email)
        
        for alias in y360_user.get('aliases', []):
            alias_lower = alias.lower().strip()
            if alias_lower:
                y360_emails.add(alias_lower)
        
        for contact in y360_user.get('contacts', []):
            if contact.get('type') == 'email':
                contact_email = contact.get('value', '').lower().strip()
                if contact_email:
                    y360_emails.add(contact_email)
        
        # Если хотя бы один email пользователя Я360 есть в AD (основной или алиас) — считаем его активным
        is_in_ad = bool(y360_emails & ad_emails)
        
        if is_in_ad:
            continue
        
        if y360_user.get('isRobot'):
            skipped_robots += 1
            continue
        
        current_dept = str(y360_user.get('departmentId', '1'))
        is_enabled = y360_user.get('isEnabled', True)
        
        target_dept = blocked_dept_id if not is_enabled else '1'
        status_text = "Заблокированный" if not is_enabled else "Активный"
        
        primary_email = main_email or (list(y360_emails)[0] if y360_emails else 'unknown')
        
        if current_dept != str(target_dept):
            if not dry_run:
                batch_updates.append((y360_user['id'], {'departmentId': int(target_dept)}))
                logger.debug(f"В пакет: {status_text} {primary_email} {current_dept} -> {target_dept}")
            else:
                logger.info(f"[DRY_RUN] {status_text} {primary_email}: {current_dept} -> {target_dept}")
            moved_count += 1

    if skipped_robots > 0:
        logger.info(f"Пропущено роботизированных учётных записей: {skipped_robots}")

    if batch_updates:
        logger.info(f"Обработка отсутствующих: отправляем пакет из {len(batch_updates)} перемещений...")
        if not dry_run:
            try:
                results = organization.patch_user_info(batch_updates)
                success_count = sum(1 for r in results if r is not None)
                logger.info(f"✓ Перемещено в корень/заблокированные: {success_count}/{len(batch_updates)}")
            except Exception as e:
                logger.error(f"✗ Критическая ошибка пакетного перемещения: {e}")
        else:
            logger.info(f"[DRY_RUN] Планируется перемещение {len(batch_updates)} пользователей.")
    else:
        logger.info("Пользователей, отсутствующих в AD и требующих перемещения, не найдено.")

# ============================================================================
# ОСНОВНОЙ ПРОЦЕСС
# ============================================================================

def compare_and_sync(organization: API360, dry_run: bool = False):
    logger.info("=== Начало синхронизации ===")
    
    logger.info("Загрузка подразделений и пользователей из AD...")
    all_ad_deps = get_ldap_departments()
    ad_users = get_ldap_users()
    
    root_dn = normalize_dn(os.environ.get('DEPARTMENT_ROOT', ''))
    logger.info(f"Корневой DN: '{root_dn or 'не задан'}'")
    
    logger.info("Фильтрация активных подразделений...")
    active_deps = build_active_departments_tree(all_ad_deps, ad_users, root_dn)
    logger.info(f"Активных подразделений для синхронизации: {len(active_deps)} из {len(all_ad_deps)}")
    
    logger.info("Синхронизация иерархии подразделений...")
    ad_to_y360_id = sync_departments_hierarchy(organization, active_deps, root_dn, dry_run)
    
    if ad_users:
        logger.info("Параллельный запуск: назначение пользователей + обработка уволенных...")
        
        # Запускаем обе задачи параллельно в отдельных потоках
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_assign = executor.submit(
                assign_users_to_departments, 
                organization, ad_users, ad_to_y360_id, all_ad_deps, root_dn, dry_run
            )
            future_reset = executor.submit(
                reset_dismissed_users_to_root, 
                organization, ad_users, dry_run
            )
            
            # Ждём завершения обеих задач
            concurrent.futures.wait([future_assign, future_reset])
            
            # Проверяем на исключения
            for f in [future_assign, future_reset]:
                exc = f.exception()
                if exc:
                    logger.error(f"Ошибка в параллельной задаче: {exc}")
        
        logger.info("Параллельные задачи завершены.")
        
    logger.info("=== Синхронизация завершена ===")

# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

if __name__ == "__main__":
    setup_logging()
    denv_path = os.path.join(os.path.dirname(__file__), '.env_ldap')
    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path, verbose=True, override=True)
    else:
        logger.error(f"Файл конфигурации {denv_path} не найден"); sys.exit(1)
        
    org_id = os.environ.get('orgId')
    token = os.environ.get('token')
    if not org_id or not token:
        logger.error("Не заданы orgId или token"); sys.exit(1)
        
    organization = API360(org_id, token)
    if not organization.check_connections_for_deps():
        logger.error("Не удалось подключиться к API Яндекс 360"); sys.exit(1)
        
    dry_run = os.environ.get('DRY_RUN', 'False').lower() in ['true', '1', 'yes']
    if dry_run: logger.info("⚠️ DRY_RUN включен")
        
    try:
        compare_and_sync(organization, dry_run=dry_run)
    except KeyboardInterrupt:
        logger.warning("Прервано пользователем"); sys.exit(130)
    except Exception as e:
        logger.error(f"Необработанная ошибка: {e}", exc_info=True); sys.exit(1)