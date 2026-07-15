import os
import sys
import ssl
import logging
import logging.handlers as handlers
from dotenv import load_dotenv
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, set_config_parameter, ServerPool, ROUND_ROBIN
from ldap3.core.exceptions import LDAPBindError, LDAPKeyError
from lib.y360_api.api_script import API360
import json
#from typing import List, Dict, Union, Any, Tuple, Optional
from typing import Optional

# --- Конфигурация по умолчанию ---
DEFAULT_LDAP_SEARCH_FILTER_CONTACTS = "(&(objectClass=contact)(mail=*)(!(msExchHideFromAddressLists=TRUE)))"
DEFAULT_ATTRIB_LDAP_LIST_CONTACTS = 'givenName,displayName,sn,initials,title,company,department,postalCode,co,st,l,streetAddress,physicalDeliveryOfficeName,objectGUID,mail,telephoneNumber,facsimileTelephoneNumber,mobile,homePhone,ipPhone'

DEFAULT_CONTACT_FIRSTNAME = 'givenName,displayName'
DEFAULT_CONTACT_LASTNAME = 'sn'
DEFAULT_CONTACT_MIDDLENAME = 'initials'
DEFAULT_CONTACT_TITLE = 'title'
DEFAULT_CONTACT_COMPANY = 'company'
DEFAULT_CONTACT_DEPARTMENT = 'department'
DEFAULT_CONTACT_ADDRESS = 'postalCode,co,st,l,streetAddress,physicalDeliveryOfficeName'
DEFAULT_CONTACT_EXTERNALID = 'objectGUID'

# Маппинг телефонов AD -> Y360
# Порядок определяет приоритет для "main" внутри типа, если не указан явно
PHONE_MAP_ORDER = [
    'telephoneNumber',
    'facsimileTelephoneNumber',
    'mobile',
    'homePhone',
    'ipPhone'
]

LOG_FILE = "sync_external_contacts.log"

logger = logging.getLogger("sync_external_contacts")
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=20, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

logger.addHandler(console_handler)
logger.addHandler(file_handler)


def parse_env_list(env_value, default_value=None):
    """
    Парсит строку из .env (разделенную запятыми) в список строк.
    """
    if not env_value or not env_value.strip():
        return default_value if isinstance(default_value, list) else [default_value]
    
    items = [item.strip() for item in env_value.split(',') if item.strip()]
    return items if items else (default_value if isinstance(default_value, list) else [default_value])

def get_safe_val(val_obj, default=""):
    """
    Безопасное извлечение значения из ldap3 object.
    Если значение — список, берет первый элемент.
    Если значение — bytes, преобразует в строку.
    """
    if not val_obj:
        return default
    
    raw_val = val_obj.value
    
    # Обработка многозначных атрибутов (списки)
    if isinstance(raw_val, list):
        raw_val = raw_val[0]
    
    if raw_val is None:
        return default
        
    # Обработка bytes (например, objectGUID)
    if isinstance(raw_val, bytes):
        return raw_val.hex()
        
    return str(raw_val).strip()

def get_ldap_contacts():
    """
    Загрузка внешних контактов из Active Directory.
    """
    set_config_parameter('DEFAULT_SERVER_ENCODING', 'utf-8')
    set_config_parameter('ADDITIONAL_SERVER_ENCODINGS', 'koi8-r')

    ldap_host_env = os.environ.get('LDAP_HOST', '')
    ldap_hosts = [h.strip() for h in ldap_host_env.split(',') if h.strip()]

    if not ldap_hosts:
        logger.error("Ошибка: Переменная LDAP_HOST пуста или не задана в .env_ldap!")
        sys.exit(1)

    ldap_port = int(os.environ.get('LDAP_PORT', 636))
    ldap_user = os.environ.get('LDAP_USER')
    ldap_password = os.environ.get('LDAP_PASSWORD')
    ldap_base_dn = os.environ.get('LDAP_BASE_DN')

    # Специфичные фильтры для контактов
    ldap_search_filter = os.environ.get('LDAP_SEARCH_FILTER_CONTACTS', DEFAULT_LDAP_SEARCH_FILTER_CONTACTS)
    attrib_list_str = os.environ.get('ATTRIB_LDAP_LIST_CONTACTS', DEFAULT_ATTRIB_LDAP_LIST_CONTACTS)
    attrib_list = [attr.strip() for attr in attrib_list_str.split(',') if attr.strip()]

    # SSL настройки
    use_ssl_env = os.environ.get('LDAP_USE_SSL', 'False').lower()
    use_ssl = use_ssl_env in ['true', '1', 'yes']
    validate_cert_env = os.environ.get('LDAP_VALIDATE_CERT', 'True').lower()
    validate_cert = validate_cert_env in ['true', '1', 'yes']

    tls_config = None
    if use_ssl:
        ca_path = os.environ.get('CA_ROOT_PATH')
        if validate_cert:
            if ca_path and os.path.exists(ca_path):
                tls_config = Tls(ca_certs_file=ca_path, validate=ssl.CERT_REQUIRED)
                if hasattr(tls_config, 'ssl_context') and tls_config.ssl_context:
                    tls_config.ssl_context.check_hostname = False
            else:
                logger.error(f"Критическая ошибка: Валидация включена, но файл сертификата не найден по пути: {ca_path}")
                sys.exit(1)
        else:
            tls_config = Tls(validate=ssl.CERT_NONE)

    server_list = [
        Server(host, port=ldap_port, use_ssl=use_ssl, tls=tls_config, get_info=ALL) 
        for host in ldap_hosts
    ]
    
    pool = ServerPool(server_list, ROUND_ROBIN, active=True, exhaust=True)
    contacts = {}
    conn = None
    
    try:
        logger.info("Попытка установить соединение с LDAP пулом для контактов...")
        conn = Connection(pool, user=ldap_user, password=ldap_password, receive_timeout=10)
        try:
            if not conn.bind():
                logger.error(f"Не удалось выполнить Bind. Результат: {conn.result}")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Критическая ошибка при открытии сокета: {e}")
            sys.exit(1)

    except LDAPBindError as e:
        logger.error('Can not connect to LDAP for contacts. Exit.')
        return {}
    except Exception as e:
        logger.error(f"{type(e).__name__}: {e}")
        return {}
        
    ldap_results = []
    cookie = None
    paged_size = 1000
    try:
        while True:
            conn.search(ldap_base_dn, ldap_search_filter, search_scope=SUBTREE, attributes=attrib_list, paged_size=paged_size, paged_cookie=cookie)
            
            if conn.last_error is not None:
                logger.error('Can not connect to LDAP for contacts. Error: %s', conn.last_error)
                return {}
            
            ldap_results.extend(conn.entries)
            
            cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
            if not cookie:
                break
    except Exception as e:
        logger.error(f"Ошибка при поиске LDAP: {e}")
    finally:
        if conn and conn.bound:
            conn.unbind()

    # --- Чтение настроек сопоставления ---
    fname_env = os.environ.get('CONTACT_FIRSTNAME', DEFAULT_CONTACT_FIRSTNAME)
    lname_env = os.environ.get('CONTACT_LASTNAME', DEFAULT_CONTACT_LASTNAME)
    mname_env = os.environ.get('CONTACT_MIDDLENAME', DEFAULT_CONTACT_MIDDLENAME)
    title_env = os.environ.get('CONTACT_TITLE', DEFAULT_CONTACT_TITLE)
    comp_env = os.environ.get('CONTACT_COMPANY', DEFAULT_CONTACT_COMPANY)
    dept_env = os.environ.get('CONTACT_DEPARTMENT', DEFAULT_CONTACT_DEPARTMENT)
    addr_env = os.environ.get('CONTACT_ADDRESS', DEFAULT_CONTACT_ADDRESS)
    extid_env = os.environ.get('CONTACT_EXTERNALID', DEFAULT_CONTACT_EXTERNALID)

    fname_fields = parse_env_list(fname_env)
    lname_fields = parse_env_list(lname_env)
    mname_fields = parse_env_list(mname_env)
    addr_fields = parse_env_list(addr_env)

    for item in ldap_results:
        try:
            # 1. Получаем и проверяем Email
            mail_val_obj = item['mail']
            if mail_val_obj.value is None or len(str(mail_val_obj.value).strip()) == 0:
                continue

            mail_val_str = str(mail_val_obj.value).strip()
            # Обработка случая, если mail приходит списком (редко, но возможно)
            if isinstance(mail_val_obj.value, list):
                mail_val_str = str(mail_val_obj.value[0]).strip() if mail_val_obj.value else ""
            
            if not mail_val_str:
                continue

            mail_lower = mail_val_str.lower()
            
            ad_data = {}
            
            # Вспомогательная функция для безопасного получения значения атрибута
            # Возвращает строку или пустую строку
            def get_attr_value(attr_name):
                try:
                    val_obj = item[attr_name]
                    if val_obj.value is None:
                        return ""
                    val_str = str(val_obj.value)
                    # Если значение список, берем первый элемент
                    if isinstance(val_obj.value, list) and len(val_obj.value) > 0:
                        val_str = str(val_obj.value[0])
                    return val_str.strip()
                except (LDAPKeyError, AttributeError):
                    return ""

            # 2. Имя (first name)
            ad_data['firstName'] = " "
            for field in fname_fields:
                raw = get_attr_value(field)
                if raw:
                    ad_data['firstName'] = raw
                    break

            # 3. Фамилия (last name)
            ad_data['lastName'] = " "
            for field in lname_fields:
                raw = get_attr_value(field)
                if raw:
                    ad_data['lastName'] = raw
                    break

            # 4. Отчество (middle name)
            ad_data['middleName'] = ""
            if mname_fields:
                for field in mname_fields:
                    raw = get_attr_value(field)
                    if raw:
                        ad_data['middleName'] = raw
                        break

            # 5. Должность (title)
            ad_data['title'] = ""
            for field in parse_env_list(title_env):
                raw = get_attr_value(field)
                if raw:
                    ad_data['title'] = raw
                    break

            # 6. Компания (company)
            ad_data['company'] = ""
            for field in parse_env_list(comp_env):
                raw = get_attr_value(field)
                if raw:
                    ad_data['company'] = raw
                    break

            # 7. Подразделение (department)
            ad_data['department'] = ""
            for field in parse_env_list(dept_env):
                raw = get_attr_value(field)
                if raw:
                    ad_data['department'] = raw
                    break
            
            # 8. Внешний ID (GUID)
            ad_data['externalId'] = ""
            for field in parse_env_list(extid_env):
                raw = get_attr_value(field)
                if raw:
                    # Для GUID нужно убедиться, что это hex string, если он пришел как bytes
                    # get_attr_value уже сделал str(), но для GUID часто лучше .hex()
                    # Проверяем, если это bytes, преобразуем, иначе оставляем как есть (так как get_attr_value делает str())
                    val_obj = item[field]
                    if val_obj.value is not None:
                         if isinstance(val_obj.value, bytes):
                             ad_data['externalId'] = val_obj.value.hex()
                         else:
                             ad_data['externalId'] = get_attr_value(field)
                    break

            # 9. Адрес
            address_parts = []
            for field in addr_fields:
                raw = get_attr_value(field)
                if raw:
                    address_parts.append(raw)
            ad_data['address'] = ", ".join(address_parts) if address_parts else ""

            # 10. Сбор телефонов
            phones_by_type = {}
            
            for attr in PHONE_MAP_ORDER:
                try:
                    val_obj = item[attr]
                    if val_obj.value is not None:
                        # Нормализация в список
                        raw_phones = val_obj.value if isinstance(val_obj.value, list) else [val_obj.value]
                        
                        y360_type = 'work'
                        if attr == 'mobile': y360_type = 'mobile'
                        elif attr == 'ipPhone': y360_type = 'ip'
                        elif attr == 'homePhone': y360_type = ''
                        elif attr == 'facsimileTelephoneNumber': y360_type = 'work'

                        for raw_phone in raw_phones:
                            rp = str(raw_phone).strip() if raw_phone else ""
                            if rp:
                                # Убираем дубли внутри одного атрибута AD
                                if not any(p['phone'] == rp for p in phones_by_type.get(y360_type, [])):
                                    if y360_type not in phones_by_type:
                                        phones_by_type[y360_type] = []
                                    phones_by_type[y360_type].append({
                                        "phone": rp,
                                        "type": y360_type,
                                        "main": False
                                    })
                except (LDAPKeyError, AttributeError):
                    continue

            # Присвоение флага main
            final_phones_list = []
            for p_type, p_list in phones_by_type.items():
                if p_list:
                    p_list[0]["main"] = True
                    final_phones_list.extend(p_list)

            ad_data['phones'] = final_phones_list

            # Email
            ad_data['emails'] = [{
                "email": mail_lower,
                "type": "work",
                "main": True
            }]

            contacts[mail_lower] = ad_data

        except Exception as e:
            logger.error(f"Ошибка обработки контакта {item['mail'].value if 'mail' in item else 'Unknown'}: {type(e).__name__}: {e}")
            continue

    logger.debug(f"Полученные контакты из домена: {contacts}")

    return contacts

def get_file_contacts(filename="y360_contacts_export.csv"):
    """
    Загрузка контактов из CSV файла с полной сборкой JSON в памяти.
    Устойчив к перемешиванию строк одного контакта в разных частях файла.
    """
    if not os.path.exists(filename):
        logger.warning(f"Файл {filename} не найден. Возврат пустого списка.")
        return {}
    import csv
    
    # Реестр: ключ -> данные контакта
    registry = {}
    
    # Переменные для «спуска» контекста текстовых полей
    last_ln = " "
    last_fn = " "
    last_mn = ""
    last_comp = ""
    last_title = ""
    last_dept = ""
    last_addr = ""

    try:
        with open(filename, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # 1. Наследование текстовых полей
                ln = row.get('last_name', '').strip() or last_ln
                fn = row.get('first_name', '').strip() or last_fn
                mn = row.get('middle_name', '').strip() or last_mn
                comp = row.get('company', '').strip() or last_comp
                title = row.get('title', '').strip() or last_title
                dept = row.get('department', '').strip() or last_dept
                addr = row.get('address', '').strip() or last_addr
                
                # Обновляем контекст
                last_ln, last_fn, last_mn = ln, fn, mn
                last_comp, last_title, last_dept, last_addr = comp, title, dept, addr
                
                # 2. Ключ группировки
                person_key = f"{ln}_{fn}_{mn}_{comp}".lower().replace(" ", "")
                if not person_key or person_key == "___":
                    continue 

                if person_key not in registry:
                    registry[person_key] = {
                        "firstName": fn,
                        "lastName": ln,
                        "middleName": mn,
                        "title": title,
                        "company": comp,
                        "department": dept,
                        "address": addr,
                        "emails": [],
                        "phones": []
                    }
                
                contact = registry[person_key]
                
                # 3. Сбор Email
                row_email = row.get('email', '').strip()
                if row_email:
                    is_main_email = row.get('is_main_email', '').strip().lower() in ['true', '1', 'yes']
                    email_type = row.get('email_type', '').strip() or 'work'
                    
                    new_email_obj = {
                        "email": row_email.lower(),
                        "type": email_type,
                        "main": is_main_email
                    }
                    
                    # Защита от дублей
                    if not any(e['email'] == row_email.lower() for e in contact['emails']):
                        contact['emails'].append(new_email_obj)

                # 4. Сбор Телефонов
                row_phone = row.get('phone_number', '').strip()
                if row_phone:
                    is_main_phone = row.get('is_main_phone_number', '').strip().lower() in ['true', '1', 'yes']
                    phone_type = row.get('phone_number_type', '').strip() or 'work'
                    
                    new_phone_obj = {
                        "phone": row_phone,
                        "type": phone_type,
                        "main": is_main_phone
                    }
                    
                    # Защита от дублей
                    if not any(p['phone'] == row_phone for p in contact['phones']):
                        contact['phones'].append(new_phone_obj)

        # --- Пост-обработка ---
        final_contacts = {}
        for person_key, contact in registry.items():
            if not contact['emails']:
                continue
                
            # Нормализация флагов main для email
            emails = contact['emails']
            if not any(e['main'] for e in emails):
                if emails: emails[0]['main'] = True
            
            # Выбор ключа (основной email)
            main_email = next((e['email'] for e in emails if e['main']), emails[0]['email'])
            
            # Нормализация флагов main для телефонов
            phones = contact['phones']
            if phones:
                # 1. Сначала ищем, был ли в CSV явно указан ХОТЯ БЫ ОДИН main=True
                has_any_explicit_main = any(p.get('main') for p in phones)
                
                if has_any_explicit_main:
                    # Вариант А: Администратор сам расставил флаги.
                    # Нам нужно только гарантировать, что в рамках одного типа остался ровно один main=True
                    seen_types_explicit = set()
                    for p in phones:
                        p_type = p['type']
                        if p.get('main'):
                            if p_type not in seen_types_explicit:
                                seen_types_explicit.add(p_type)
                                p['main'] = True # Первый main для этого типа оставляем
                            else:
                                p['main'] = False # Дублирующие main для этого же типа сбрасываем
                        else:
                            p['main'] = False # Все остальные гарантированно False
                else:
                    # Вариант Б: Явных флагов в CSV не было вообще.
                    # Автоматически ставим main=True самому первому телефону каждого типа
                    seen_types_auto = set()
                    for p in phones:
                        p_type = p['type']
                        if p_type not in seen_types_auto:
                            p['main'] = True
                            seen_types_auto.add(p_type)
                        else:
                            p['main'] = False

            final_contacts[main_email] = contact

        logger.info(f"Успешно обработан CSV. Собрано уникальных контактов: {len(final_contacts)}")
        return final_contacts

    except Exception as e:
        logger.error(f"Ошибка при обработке CSV файла {filename}: {e}")
        return {}

def get_y360_contacts(organization: API360) -> Optional[dict]:
    """
    Загрузка всех внешних контактов из Яндекс 360.
    
    :param organization: Экземпляр API360
    :return: Словарь {externalId: contact_object} при успехе,
             пустой словарь {} если контактов нет,
             None при ошибке загрузки API.
    """
    logger.info("Загрузка внешних контактов из Яндекс 360...")
    raw_contacts = organization.get_external_contacts()

    # ВАЖНО: явная проверка на None — сигнал фатальной ошибки API
    # Подробные логи ошибки уже выведены в _make_api_request_async
    if raw_contacts is None:
        logger.error(
            "Не удалось загрузить внешние контакты из Y360. "
            "Синхронизация прервана для предотвращения потери данных. "
            "Проверьте токен, сеть и логи [API] выше."
        )
        return None

    y360_db = {}
    if not raw_contacts:
        logger.warning(
            "Список контактов из Y360 пуст. "
            "Если это не новая организация — проверьте состояние API."
        )
        return {}

    for contact in raw_contacts:
        ext_id = contact.get('externalId')
        
        # Индексируем по externalId если есть, иначе по ID
        key = ext_id if ext_id else contact.get('id')
        if key:
            y360_db[key] = contact
            
    logger.info(f"Загружено {len(y360_db)} контактов из Яндекс 360.")
    return y360_db

def normalize_phones_for_comparison(phones: list) -> set:
    """
    Нормализует список телефонов для сравнения.
    Преобразует поле 'main' из строки в boolean для корректного сравнения.
    
    :param phones: Список словарей с телефонами
    :return: Множество кортежей (phone, type, main_as_bool)
    """
    normalized = set()
    for p in phones:
        phone = p.get('phone')
        phone_type = p.get('type')
        main = p.get('main')
        
        # Нормализация main: строка "True"/"False" → boolean
        if isinstance(main, str):
            main_bool = main.lower() in ['true', '1', 'yes']
        else:
            main_bool = bool(main)
        
        normalized.add((phone, phone_type, main_bool))
    
    return normalized

def compare_and_sync_contacts(organization: API360, dry_run: bool = False):
    """
    Основная логика синхронизации внешних контактов между AD и Y360.
    
    :param organization: Экземпляр API360
    :param dry_run: Если True, изменения не применяются
    """
    logger.info("--- Начало синхронизации внешних контактов ---")
    
    # 1. Получаем данные из AD
    ad_contacts = get_ldap_contacts()
    if not ad_contacts:
        logger.warning("Список контактов из AD пуст. Прерывание синхронизации.")
        return

    logger.info(f"Получено {len(ad_contacts)} контактов из Active Directory.")

    # 2. Получаем данные из Y360
    y360_contacts = get_y360_contacts(organization)

    # ВАЖНО: если y360_contacts = None, это ошибка API — прерываемся
    if y360_contacts is None:
        logger.error(
            "Синхронизация прервана: не удалось загрузить состояние Y360. "
            "Без актуального списка нельзя безопасно выполнять diff-операции."
        )
        return

    # 3. Индексация по externalId
    # AD контакты: маппим их по externalId
    ad_by_ext_id = {}
    for mail, data in ad_contacts.items():
        ext_id = data.get('externalId')
        if ext_id:
            ad_by_ext_id[ext_id] = data
        # Если externalId нет, можно добавить фоллбэк, но для strict sync будем работать только с GUID
        else:
            logger.debug(f"Контакт {mail} не имеет externalId в AD. Будет пропущен при сравнении по GUID.")

    ad_ext_keys = set(ad_by_ext_id.keys())
    y360_ext_keys = set(y360_contacts.keys())
    
    to_create_ext = ad_ext_keys - y360_ext_keys
    to_delete_ext = y360_ext_keys - ad_ext_keys
    to_update_ext = ad_ext_keys & y360_ext_keys
    
    to_delete_ids = [y360_contacts[ext]['id'] for ext in to_delete_ext if 'id' in y360_contacts[ext]]
    
    # 4. Подготовка пакетов на создание
    create_payloads = []
    for ext_id in to_create_ext:
        ad_data = ad_by_ext_id[ext_id]
        
        payload = {
            "firstName": ad_data.get('firstName', ''),
            "lastName": ad_data.get('lastName', ''),
            "middleName": ad_data.get('middleName', ''),
            "title": ad_data.get('title', ''),
            "company": ad_data.get('company', ''),
            "department": ad_data.get('department', ''),
            "address": ad_data.get('address', ''),
            "externalId": ad_data.get('externalId', ''),
            "emails": ad_data.get('emails', []),
            "phones": ad_data.get('phones', [])
        }
        
        # Умное заполнение lastName
        if not payload.get('lastName'):
            # Если фамилия пустая, ставим точку, чтобы API принял контакт
            payload['lastName'] = " "
            logger.debug(f"Фамилия для контакта {ext_id} пустая, установлена '.'")

        # Логирование JSON для отладки
        logger.debug(f"Подготовка к созданию контакта (externalId: {ext_id}):")
        logger.debug(f"  Данные из AD: firstName='{ad_data.get('firstName', '')}', lastName='{ad_data.get('lastName', '')}'")
        logger.debug(f"  Отправляемый JSON: {json.dumps(payload, ensure_ascii=False, indent=2)}")
        
        create_payloads.append(payload)

    # 5. Подготовка пакетов на обновление
    to_update_emails_batch = []
    to_update_phones_batch = []
    to_update_info_batch = []
    
    for ext_id in to_update_ext:
        ad_data = ad_by_ext_id[ext_id]
        y360_data = y360_contacts[ext_id]
        y360_id = y360_data.get('id')
        
        if not y360_id:
            continue

        # Email
        y360_emails = y360_data.get('emails', [])
        ad_emails = ad_data.get('emails', [])
        
        # Сравнение наборов email
        y360_email_set = {e.get('email') for e in y360_emails}
        ad_email_set = {e.get('email') for e in ad_emails}
        
        if y360_email_set != ad_email_set:
            to_update_emails_batch.append((y360_id, ad_emails))
        
        # Phones
        y360_phones = y360_data.get('phones', [])
        ad_phones = ad_data.get('phones', [])
        
        # Используем нормализацию для корректного сравнения
        y360_phones_set = normalize_phones_for_comparison(y360_phones)
        ad_phones_set = normalize_phones_for_comparison(ad_phones)

        if ad_phones:
            logger.debug(f"Изменения для контакта {y360_id} (extId: {ext_id}):")
            logger.debug(f"  Отправляемые данные по телефонам: {json.dumps(ad_phones, ensure_ascii=False, indent=2)}")

        if y360_phones_set != ad_phones_set:
            to_update_phones_batch.append((y360_id, ad_phones))
            
        # Meta
        info_changes = {}
        
        # Сравниваем поля без проверки на пустоту (чтобы очищать поля)
        fields_to_check = ['firstName', 'lastName', 'middleName', 'title', 'company', 'department', 'address', 'externalId']
        for field in fields_to_check:
            ad_val = ad_data.get(field, '')
            y360_val = y360_data.get(field, '')
            if ad_val != y360_val:
                info_changes[field] = ad_val
            
        # --- НОВОЕ ЛОГИРОВАНИЕ ---
        # Логирование даже если изменений нет (для отладки), или если они есть
        # Используем DEBUG, чтобы не засорять лог, если контактов много
        if info_changes:
            logger.debug(f"Изменения для контакта {y360_id} (extId: {ext_id}):")
            logger.debug(f"  Отправляемые данные: {json.dumps(info_changes, ensure_ascii=False, indent=2)}")

        if info_changes:
            to_update_info_batch.append({"id": y360_id, "data": info_changes})

    # 6. Выполнение операций

    # 6.1 Удаление
    if to_delete_ids:
        logger.info(f"Удаление {len(to_delete_ids)} контактов из Яндекс 360...")
        if not dry_run:
            try:
                results = organization.delete_external_contact(to_delete_ids)
                success = sum(1 for r in results if r.get('status') in ['success', 'not_found'])
                logger.info(f"Удаление завершено. Успешно: {success}/{len(results)}")
                
                # Детальный вывод ошибок удаления
                for r in results:
                    status = r.get('status', 'unknown')
                    if status not in ['success', 'not_found']:
                        contact_id = r.get('contact_id', 'N/A')
                        message = r.get('message', 'Нет информации об ошибке')
                        logger.error(f"Ошибка удаления контакта {contact_id}: {message} (статус: {status})")
                        
            except Exception as e:
                logger.error(f"Ошибка при удалении: {e}")
        else:
            logger.info(f"[DRY_RUN] Планируется удаление {len(to_delete_ids)} контактов.")

    # 6.2 Создание
    if create_payloads:
        logger.info(f"Создание {len(create_payloads)} новых контактов в Яндекс 360...")
        if not dry_run:
            try:
                results = organization.post_create_external_contacts_batch(create_payloads)
                success = sum(1 for r in results if r.get('success'))
                failed = len(results) - success
                logger.info(f"Создание завершено. Успешно: {success}, Ошибок: {failed}")
                if failed > 0:
                    for r in results:
                        if not r.get('success'):
                            logger.error(f"Ошибка создания контакта: {r.get('error')}")
            except Exception as e:
                logger.error(f"Ошибка при создании: {e}")
        else:
            logger.info(f"[DRY_RUN] Планируется создание {len(create_payloads)} контактов.")

    # 6.3 Обновление телефонов
    if to_update_phones_batch:
        logger.info(f"Обновление телефонов для {len(to_update_phones_batch)} контактов...")
        if not dry_run:
            try:
                results = organization.patch_external_contact_phones(to_update_phones_batch)
                success = sum(1 for r in results if r.get('success'))
                logger.info(f"Обновление телефонов завершено. Успешно: {success}/{len(results)}")
                for r in results:
                    if not r.get('success'):
                        logger.error(f"Ошибка обновления телефона: {r.get('error')}")
            except Exception as e:
                logger.error(f"Ошибка при обновлении телефонов: {e}")
        else:
            logger.info(f"[DRY_RUN] Планируется обновление телефонов для {len(to_update_phones_batch)} контактов.")

    # 6.4 Обновление Email
    if to_update_emails_batch:
        logger.info(f"Обновление Email для {len(to_update_emails_batch)} контактов...")
        if not dry_run:
            try:
                results = organization.patch_external_contact_emails(to_update_emails_batch)
                success = sum(1 for r in results if r.get('success'))
                logger.info(f"Обновление Email завершено. Успешно: {success}/{len(results)}")
                for r in results:
                    if not r.get('success'):
                        logger.error(f"Ошибка обновления Email: {r.get('error')}")
            except Exception as e:
                logger.error(f"Ошибка при обновлении Email: {e}")
        else:
            logger.info(f"[DRY_RUN] Планируется обновление Email для {len(to_update_emails_batch)} контактов.")

    # 6.5 Обновление мета-данных
    if to_update_info_batch:
        logger.info(f"Обновление мета-данных для {len(to_update_info_batch)} контактов...")
        if not dry_run:
            try:
                results = organization.patch_external_contacts_batch_heterogeneous(to_update_info_batch)
                success = sum(1 for r in results if r.get('success'))
                logger.info(f"Обновление мета-данных завершено. Успешно: {success}/{len(results)}")
                for r in results:
                    if not r.get('success'):
                        logger.error(f"Ошибка обновления мета-данных: {r.get('error')}")
            except Exception as e:
                logger.error(f"Ошибка при обновлении мета-данных: {e}")
        else:
            logger.info(f"[DRY_RUN] Планируется обновление мета-данных для {len(to_update_info_batch)} контактов.")

    logger.info("--- Конец синхронизации внешних контактов ---")


if __name__ == "__main__":
    denv_path = os.path.join(os.path.dirname(__file__), '.env_ldap')
    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path, verbose=True, override=True)
    else:
        logger.error(f"Файл {denv_path} не найден!")
        sys.exit(1)

    organization = API360(os.environ.get('orgId'), os.environ.get('token'))

    logger.info('Подключение к Яндекс 360...')
    try:
        # Health-check: пробуем загрузить внешние контакты
        org_test = organization.get_external_contacts()
        
        # Явная проверка: None = ошибка соединения/авторизации
        if org_test is None:
            logger.error(
                "Не удалось подключиться к API внешних контактов. "
                "Проверьте токен, orgId, сетевой доступ и логи [API] выше."
            )
            sys.exit(1)
        
        logger.info(f"Соединение с Яндекс 360 успешно. "
                   f"Найдено внешних контактов: {len(org_test)}")
    except Exception as e:
        logger.error(f"Исключение при подключении к Яндекс 360: {type(e).__name__}: {e}")
        sys.exit(1)

    dry_run = os.environ.get('DRY_RUN', 'False').lower() in ['true', '1']
    if dry_run:
        logger.info('- Режим тестового прогона включен (DRY_RUN = True)! Изменения не сохраняются! -')

    logger.info('---------------Start External Contacts Sync-----------------')
    compare_and_sync_contacts(organization, dry_run=dry_run)
    logger.info('---------------End External Contacts Sync-----------------')
