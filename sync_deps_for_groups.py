import os
import sys
import ssl
import logging
import logging.handlers as handlers
import json
from typing import Dict, List, Tuple, Optional, Set, Any
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, set_config_parameter, ServerPool, ROUND_ROBIN
from ldap3.core.exceptions import LDAPBindError, LDAPKeyError
from dotenv import load_dotenv
from lib.y360_api.api_script import API360

# --- Конфигурация по умолчанию ---
DEFAULT_LDAP_SEARCH_FILTER_GROUP = "(&(objectClass=group)(mail=*@domain)(!(msExchHideFromAddressLists=TRUE))(!(name=Администраторы))(!(name=Администраторы домена)))"
DEFAULT_ATTRIB_LDAP_LIST_GROUP = 'description,objectGUID,mailNickname,displayName,mail,member,memberOf'
DEFAULT_GROUP_DESCRIPTION = 'description'
DEFAULT_GROUP_EXTERNALID = 'objectGUID'
DEFAULT_GROUP_LABEL = 'mailNickname'
DEFAULT_GROUP_NAME = 'displayName'
DEFAULT_GROUP_EMAIL = 'mail'
DEFAULT_GROUP_MEMBERS = 'member'
DEFAULT_GROUP_MEMBEROF = 'memberOf'

LOG_FILE = "sync_external_groups.log"
logger = logging.getLogger("sync_external_groups")
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=20, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

logger.addHandler(console_handler)
logger.addHandler(file_handler)


def parse_env_list(env_value: str, default_value: Optional[List] = None) -> List[str]:
    """Парсит строку из .env (разделенную запятыми) в список строк."""
    if not env_value or not env_value.strip():
        return default_value if isinstance(default_value, list) else [default_value] if default_value else []
    items = [item.strip() for item in env_value.split(',') if item.strip()]
    return items if items else (default_value if isinstance(default_value, list) else [default_value])


def get_safe_val(val_obj, default: str = "") -> str:
    """Безопасное извлечение значения из ldap3 object."""
    if not val_obj:
        return default
    raw_val = val_obj.value
    if isinstance(raw_val, list):
        raw_val = raw_val[0]
    if raw_val is None:
        return default
    if isinstance(raw_val, bytes):
        return raw_val.hex()
    return str(raw_val).strip()

def normalize_external_id(raw_id: str) -> str:
    """
    Очищает externalId от фигурных скобок, типичных для AD objectGUID,
    и приводит к нижнему регистру для единообразия.
    :param raw_id: Сырое значение из AD
    :return: Очищенная строка
    """
    if not raw_id:
        return ""
    return raw_id.strip().replace("{", "").replace("}", "").lower()

def resolve_ad_dns(conn: Connection, dns: Set[str]) -> Dict[str, Dict[str, Any]]:
    """
    Резолвит список Distinguished Names (DN) в AD в словарь с метаданными.
    :param conn: Активное соединение ldap3
    :param dns: Множество уникальных DN для резолвинга
    :return: dict {dn: {'guid': str, 'mail': str, 'type': 'user'|'group'}}
    """
    cache = {}
    if not dns:
        return cache

    logger.debug(f"Резолвинг {len(dns)} DN из Active Directory...")
    for dn in dns:
        try:
            conn.search(search_base=dn, search_filter='(objectClass=*)', search_scope=SUBTREE,
                        attributes=['objectGUID', 'mail', 'objectClass'])
            
            if conn.entries:
                entry = conn.entries[0]

                # В ldap3 атрибуты доступны через entry['attr'], а не .get()
                guid_attr = entry['objectGUID'] if 'objectGUID' in entry else None
                mail_attr = entry['mail'] if 'mail' in entry else None
                class_attr = entry['objectClass'] if 'objectClass' in entry else None

                #guid = get_safe_val(guid_attr)
                guid = normalize_external_id(get_safe_val(guid_attr))
                mail = get_safe_val(mail_attr)

                # Определение типа объекта (user/group) по objectClass
                raw_class = class_attr.value if class_attr else []
                if isinstance(raw_class, str):
                    raw_class = [raw_class]
                
                # В AD objectClass обычно list: ['top', 'person', 'organizationalPerson', 'user']
                ad_type = 'group' if any('group' in str(c).lower() for c in raw_class) else 'user'

                cache[dn] = {'guid': guid, 'mail': mail, 'type': ad_type}
                
        except Exception as e:
            logger.debug(f"Не удалось резолвить DN {dn}: {e}")
            
    return cache


def get_ldap_groups() -> Dict[str, Dict[str, Any]]:
    """
    Загрузка групп рассылки из Active Directory.
    :return: Словарь {objectGUID_or_email_key: group_data}
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
    
    domain_suffix = os.environ.get('DOMAINS_ALLOW', 'domain.com')
    raw_filter = os.environ.get('LDAP_SEARCH_FILTER_GROUP', DEFAULT_LDAP_SEARCH_FILTER_GROUP)

    # Безопасная замена плейсхолдера
    if '@domain' in raw_filter:
        ldap_search_filter = raw_filter.replace('@domain', f'@{domain_suffix}')
    else:
        ldap_search_filter = raw_filter
    
    attrib_list_str = os.environ.get('ATTRIB_LDAP_LIST_GROUP', DEFAULT_ATTRIB_LDAP_LIST_GROUP)
    attrib_list = [attr.strip() for attr in attrib_list_str.split(',') if attr.strip()]

    use_ssl = os.environ.get('LDAP_USE_SSL', 'False').lower() in ['true', '1', 'yes']
    validate_cert = os.environ.get('LDAP_VALIDATE_CERT', 'True').lower() in ['true', '1', 'yes']
    
    tls_config = None
    if use_ssl:
        ca_path = os.environ.get('CA_ROOT_PATH')
        if validate_cert:
            if ca_path and os.path.exists(ca_path):
                tls_config = Tls(ca_certs_file=ca_path, validate=ssl.CERT_REQUIRED)
                if hasattr(tls_config, 'ssl_context') and tls_config.ssl_context:
                    tls_config.ssl_context.check_hostname = False
            else:
                logger.error(f"Критическая ошибка: Валидация включена, но файл сертификата не найден: {ca_path}")
                sys.exit(1)
        else:
            tls_config = Tls(validate=ssl.CERT_NONE)

    server_list = [Server(host, port=ldap_port, use_ssl=use_ssl, tls=tls_config, get_info=ALL) for host in ldap_hosts]
    pool = ServerPool(server_list, ROUND_ROBIN, active=True, exhaust=True)

    logger.info("🔍 Параметры LDAP-поиска групп:")
    logger.info(f"   Base DN:    {ldap_base_dn}")
    logger.info(f"   Filter:     {ldap_search_filter}")
    logger.info(f"   Attributes: {attrib_list}")

    conn = None
    ad_groups = {}

    try:
        logger.info("Попытка установить соединение с LDAP пулом для групп...")
        conn = Connection(pool, user=ldap_user, password=ldap_password, receive_timeout=10)
        if not conn.bind():
            logger.error(f"Не удалось выполнить Bind. Результат: {conn.result}")
            return {}

        # 1. Пагинация и загрузка групп
        groups_data = []
        cookie = None
        paged_size = 1000
        try:
            while True:
                conn.search(ldap_base_dn, ldap_search_filter, search_scope=SUBTREE, attributes=attrib_list, paged_size=paged_size, paged_cookie=cookie)
                if conn.last_error:
                    logger.error(f'Ошибка LDAP поиска групп: {conn.last_error}')
                    return {}
                groups_data.extend(conn.entries)
                cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                if not cookie:
                    break
        except Exception as e:
            logger.error(f"Ошибка при поиске LDAP групп: {e}")
            return {}

        logger.info(f"Загружено {len(groups_data)} записей групп из Active Directory.")

        # 2. Сбор всех уникальных DN из member/memberOf
        members_field = os.environ.get('GROUP_MEMBERS', DEFAULT_GROUP_MEMBERS)
        memberof_field = os.environ.get('GROUP_MEMBEROF', DEFAULT_GROUP_MEMBEROF)
        all_member_dns = set()
        
        for grp in groups_data:
            for attr_name in [members_field, memberof_field]:
                if attr_name in grp and grp[attr_name].value:
                    vals = grp[attr_name].value if isinstance(grp[attr_name].value, list) else [grp[attr_name].value]
                    all_member_dns.update([str(v).strip() for v in vals if v])

        # 3. Резолвинг DN (ВНИМАНИЕ: conn всё ещё АКТИВЕН и открыт)
        dn_cache = resolve_ad_dns(conn, all_member_dns)

        # 4. Маппинг полей
        desc_fields = parse_env_list(os.environ.get('GROUP_DESCRIPTION', DEFAULT_GROUP_DESCRIPTION))
        extid_fields = parse_env_list(os.environ.get('GROUP_EXTERNALID', DEFAULT_GROUP_EXTERNALID))
        label_fields = parse_env_list(os.environ.get('GROUP_LABEL', DEFAULT_GROUP_LABEL))
        name_fields = parse_env_list(os.environ.get('GROUP_NAME', DEFAULT_GROUP_NAME))
        email_fields = parse_env_list(os.environ.get('GROUP_EMAIL', DEFAULT_GROUP_EMAIL))

        def get_attr(entry, fields):
            for f in fields:
                if f in entry:
                    return get_safe_val(entry[f])
            return ""

        # 5. Сборка финального словаря групп
        for item in groups_data:
            try:
                #guid = get_attr(item, extid_fields)
                guid = normalize_external_id(get_attr(item, extid_fields))
                email = get_attr(item, email_fields).lower()
                if not email:
                    continue

                members_raw = []
                if members_field in item:
                    vals = item[members_field].value
                    if isinstance(vals, list): members_raw = [str(v) for v in vals]
                    elif vals: members_raw = [str(vals)]

                parent_of_raw = []
                # ИСПРАВЛЕНО: используем memberof_field, а не members_field
                if memberof_field in item:
                    vals = item[memberof_field].value
                    if isinstance(vals, list): parent_of_raw = [str(v) for v in vals]
                    elif vals: parent_of_raw = [str(vals)]

                resolved_members = [dn_cache.get(dn, {}) for dn in members_raw if dn_cache.get(dn, {}).get('guid') or dn_cache.get(dn, {}).get('mail')]
                resolved_parent_of = [dn_cache.get(dn, {}) for dn in parent_of_raw if dn_cache.get(dn, {}).get('guid') or dn_cache.get(dn, {}).get('mail')]

                group_obj = {
                    'externalId': guid,
                    'email': email,
                    'name': get_attr(item, name_fields),
                    'description': get_attr(item, desc_fields),
                    'label': get_attr(item, label_fields),
                    'members': resolved_members,
                    'memberOf': resolved_parent_of,
                }
                
                sync_key = guid if guid else f"email:{email}"
                ad_groups[sync_key] = group_obj
                
            except Exception as e:
                logger.debug(f"Ошибка обработки группы {item.get('mail', 'Unknown')}: {e}")
                continue

        return ad_groups

    except LDAPBindError as e:
        logger.error(f'Не удалось подключиться к LDAP для групп: {e}')
        return {}
    except Exception as e:
        logger.error(f"{type(e).__name__}: {e}")
        return {}
    finally:
        # Соединение закрывается ТОЛЬКО после завершения всех операций
        if conn and conn.bound:
            conn.unbind()


def fetch_y360_data(organization: API360) -> Tuple[List[Dict], List[Dict]]:
    """Получает все группы и пользователей из Яндекс 360."""
    logger.info("Загрузка групп и пользователей из Яндекс 360...")
    y360_groups = organization.get_groups_list() or []
    y360_users = organization.get_all_users() or []
    logger.info(f"Получено {len(y360_groups)} групп и {len(y360_users)} пользователей из Y360.")
    return y360_groups, y360_users


def deduplicate_y360_groups(y360_groups: List[Dict]) -> Dict[str, Dict]:
    """
    Группирует группы Y360 по externalId/email.
    Если дубликаты найдены, оставляет запись с наибольшим совпадением полей.
    Технические группы (type != 'generic') не удаляются и не модифицируются.
    :return: Словарь {externalId_or_email: group_data}
    """
    lookup = {}
    to_delete_ids = []
    
    # Системные типы групп, которые нельзя изменять
    IMMUTABLE_GROUP_TYPES = {'organization_admin', 'robots', 'organization_deputy_admin'}

    for grp in y360_groups:
        # Пропускаем технические группы — они не участвуют в синхронизации
        if grp.get('type') in IMMUTABLE_GROUP_TYPES:
            logger.debug(f"Пропущена техническая группа: {grp.get('name')} (type={grp.get('type')})")
            continue
            
        key = grp.get('externalId') or f"email:{grp.get('email', '').lower()}"
        if not key:
            continue
            
        if key not in lookup:
            lookup[key] = grp
        else:
            existing = lookup[key]
            # Простой скоринг совпадений
            score_existing = sum(1 for k in ['name', 'description', 'email'] if existing.get(k))
            score_new = sum(1 for k in ['name', 'description', 'email'] if grp.get(k))
            
            # Определяем, какую запись оставить, а какую пометить на удаление
            if score_new > score_existing:
                # Проверяем, можно ли удалить существующую запись
                if existing.get('type') not in IMMUTABLE_GROUP_TYPES:
                    to_delete_ids.append(existing['id'])
                    lookup[key] = grp
                else:
                    logger.warning(f"Дубликат группы {key}: техническая группа {existing.get('name')} не может быть удалена, оставляем её")
            else:
                # Проверяем, можно ли удалить новую запись
                if grp.get('type') not in IMMUTABLE_GROUP_TYPES:
                    to_delete_ids.append(grp['id'])
                else:
                    logger.warning(f"Дубликат группы {key}: техническая группа {grp.get('name')} не может быть удалена")
                    
    if to_delete_ids:
        logger.info(f"Найдено {len(to_delete_ids)} дубликатов групп в Y360, доступных для удаления.")
        for gid in to_delete_ids:
            # Дополнительная проверка перед удалением
            grp_to_delete = next((g for g in y360_groups if g['id'] == gid), None)
            if grp_to_delete and grp_to_delete.get('type') in IMMUTABLE_GROUP_TYPES:
                logger.warning(f"Пропущено удаление технической группы {gid}: {grp_to_delete.get('name')}")
                continue
                
            res = organization.delete_group_by_id(gid)
            if res.get('success'):
                logger.debug(f"Дубликат группы {gid} удалён.")
            elif res.get('error') and 'tech_group_modification_forbidden' in res.get('error', ''):
                logger.warning(f"Группа {gid} является системной и не может быть удалена. Пропущено.")
            else:
                logger.error(f"Ошибка удаления дубликата {gid}: {res.get('error')}")
                
    return lookup


def topological_sort_groups(ad_groups: Dict[str, Dict]) -> List[Dict]:
    """
    Сортирует группы сверху вниз на основе memberOf (только среди загруженных групп рассылки).
    Использует алгоритм Кана для топологической сортировки.
    """
    guid_map = {g.get('externalId'): g for g in ad_groups.values() if g.get('externalId')}
    email_map = {g.get('email'): g for g in ad_groups.values() if g.get('email')}
    
    adj = {g['externalId']: [] for g in ad_groups.values() if g.get('externalId')}
    in_degree = {k: 0 for k in adj}
    
    for g in ad_groups.values():
        guid = g.get('externalId')
        if not guid or guid not in adj: continue
        
        parents = g.get('memberOf', [])
        for p in parents:
            p_guid = p.get('guid')
            if p_guid and p_guid in adj:
                adj[p_guid].append(guid)
                in_degree[guid] = in_degree.get(guid, 0) + 1
                
    queue = [g for g, deg in in_degree.items() if deg == 0]
    sorted_guids = []
    
    while queue:
        node = queue.pop(0)
        sorted_guids.append(node)
        for neighbor in adj.get(node, []):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
                
    # Если остались несортированные (циклы), добавляем их в конец
    remaining = [g for g in adj if g not in sorted_guids]
    sorted_guids.extend(remaining)
    
    sorted_groups = [guid_map[g] for g in sorted_guids if g in guid_map]
    # Добавляем группы без externalId
    sorted_groups.extend([g for g in ad_groups.values() if not g.get('externalId')])
    
    return sorted_groups


def compare_and_sync_groups(organization: API360, dry_run: bool = False):
    """
    Основная логика синхронизации групп между AD и Y360.
    """
    logger.info("--- Начало синхронизации групп ---")
    
    ad_groups = get_ldap_groups()
    if not ad_groups:
        logger.warning("Список групп из AD пуст. Прерывание синхронизации.")
        return

    y360_groups_raw, y360_users = fetch_y360_data(organization)

    # === Журналирование технических групп ===
    IMMUTABLE_GROUP_TYPES = {'organization_admin', 'robots', 'organization_deputy_admin'}
    tech_groups = [g for g in y360_groups_raw if g.get('type') in IMMUTABLE_GROUP_TYPES]
    if tech_groups:
        logger.info(
            f"Обнаружено {len(tech_groups)} технических групп (не синхронизируются): "
            f"{[g.get('name') + '(' + g.get('email', 'no-email') + ')' for g in tech_groups]}"
        )
    # =====================================================

    y360_groups = deduplicate_y360_groups(y360_groups_raw)
    
    # Индексы для быстрого поиска
    y360_users_by_extid = {u.get('externalId'): u for u in y360_users if u.get('externalId')}
    y360_users_by_email = {u.get('email', '').lower(): u for u in y360_users if u.get('email')}
    y360_groups_by_extid = {g.get('externalId'): g for g in y360_groups.values() if g.get('externalId')}
    y360_groups_by_email = {g.get('email', '').lower(): g for g in y360_groups.values() if g.get('email')}

    sorted_ad_groups = topological_sort_groups(ad_groups)
    
    to_create = []
    to_update = []
    to_sync_members = []

    for ad_key, ad_grp in ad_groups.items():
        guid = ad_grp.get('externalId')
        email = ad_grp.get('email')
        
        # Поиск существующей группы в Y360
        y360_grp = None
        if guid and guid in y360_groups_by_extid:
            y360_grp = y360_groups_by_extid[guid]
        elif email and email in y360_groups_by_email:
            y360_grp = y360_groups_by_email[email]
            
        if not y360_grp:
            to_create.append(ad_grp)
        else:
            to_update.append((y360_grp, ad_grp))
            
    # 1. Создание новых групп
    if to_create:
        logger.info(f"Создание {len(to_create)} новых групп...")
        for grp in to_create:
            payload = {
                'name': grp.get('name') or 'Unnamed Group',
                'description': grp.get('description'),
                'label': grp.get('label') or grp['email'].split('@')[0],
                'externalId': grp.get('externalId')
            }

            # === Журналирование отправляемого JSON ===
            logger.debug(f"📤 [CREATE] Отправляемый JSON для группы {grp['email']}:")
            logger.debug(json.dumps(payload, ensure_ascii=False, indent=2))
            # =======================================================

            if dry_run:
                logger.info(f"[DRY_RUN] Создание: {payload}")
                continue
                
            success, msg = organization.post_create_group(payload)
            if success:
                logger.debug(f"Группа {grp['email']} успешно создана.")
            else:
                logger.error(f"Ошибка создания группы {grp['email']}: {msg}")

    # 2. Обновление метаданных существующих групп
    if to_update:
        logger.info(f"Обновление метаданных для {len(to_update)} групп...")
        for y_grp, a_grp in to_update:
            changes = {}
            if a_grp.get('name') and y_grp.get('name') != a_grp['name']:
                changes['name'] = a_grp['name']
            if a_grp.get('description') != y_grp.get('description'):
                changes['description'] = a_grp.get('description')
            if a_grp.get('label') and y_grp.get('label') != a_grp['label']:
                changes['label'] = a_grp['label']
            if a_grp.get('externalId') and y_grp.get('externalId') != a_grp['externalId']:
                changes['externalId'] = a_grp['externalId']
                
            if changes:

                # === Журналирование отправляемого JSON ===
                logger.debug(f"📤 [PATCH] Группа {y_grp['id']} ({y_grp['name']}): отправляемые изменения:")
                logger.debug(json.dumps(changes, ensure_ascii=False, indent=2))
                # =======================================================

                if dry_run:
                    logger.info(f"[DRY_RUN] Обновление {y_grp['id']}: {changes}")
                    continue
                res = organization.patch_group_info(y_grp['id'], changes)
                if res:
                    logger.debug(f"Метаданные группы {y_grp['id']} обновлены.")
                else:
                    logger.error(f"Ошибка обновления метаданных группы {y_grp['id']}")
                    logger.error(f"Метаданные группы {y_grp['id']} для обновления changes: {changes}")

    # 3. Синхронизация участников (только добавление недостающих)
    logger.info("Синхронизация состава групп...")
    for y_grp, a_grp in to_update:
        ad_members = a_grp.get('members', [])
        y360_members_raw = organization.get_group_members_by_id(y_grp['id']) or []
        # Приводим к set для быстрого сравнения (используем id)
        current_y360_ids = {m['id'] for m in y360_members_raw}
        
        members_to_add = []
        for m in ad_members:
            m_guid = m.get('guid')
            m_email = m.get('mail', '').lower()
            m_type_ad = m.get('type') # 'user' or 'group'
            
            y360_id = None
            y360_type = None
            
            # Сопоставление по externalId (приоритет)
            if m_guid:
                if m_type_ad == 'group' and m_guid in y360_groups_by_extid:
                    y360_id = str(y360_groups_by_extid[m_guid]['id'])
                    y360_type = 'group'
                elif m_type_ad == 'user' and m_guid in y360_users_by_extid:
                    y360_id = str(y360_users_by_extid[m_guid]['id'])
                    y360_type = 'user'
                    
            # Сопоставление по email (fallback)
            if not y360_id and m_email:
                if m_type_ad == 'group' and m_email in y360_groups_by_email:
                    y360_id = str(y360_groups_by_email[m_email]['id'])
                    y360_type = 'group'
                elif m_type_ad == 'user' and m_email in y360_users_by_email:
                    y360_id = str(y360_users_by_email[m_email]['id'])
                    y360_type = 'user'
                    
            if y360_id and y360_id not in current_y360_ids:
                members_to_add.append({'type': y360_type, 'id': y360_id})
                
        if members_to_add and not dry_run:
            logger.info(f"Добавление {len(members_to_add)} участников в группу {y_grp['name']} ({y_grp['id']})...")

            # === Журналирование отправляемого JSON ===
            logger.debug(f"📤 [ADD_MEMBERS] Группа {y_grp['id']}: список участников для добавления:")
            logger.debug(json.dumps(members_to_add, ensure_ascii=False, indent=2))
            # =======================================================

            res = organization.post_add_member_to_group(y_grp['id'], members_to_add)
            # Обработка результата (может быть список или дикт)
            results = res if isinstance(res, list) else [res]
            success_count = sum(1 for r in results if r.get('status') == 'success')
            if success_count < len(members_to_add):
                logger.warning(f"Часть участников не добавлена в группу {y_grp['id']}")

    # 4. Удаление групп, которых нет в AD
    y360_keys = set(y360_groups.keys())
    ad_keys = set(ad_groups.keys())
    to_delete = y360_keys - ad_keys
    
    if to_delete:
        logger.info(f"Удаление {len(to_delete)} групп, отсутствующих в AD...")
        for key in to_delete:
            grp = y360_groups[key]
            if grp.get('type') in {'organization_admin', 'robots', 'organization_deputy_admin'}:
                logger.info(f"Пропущено удаление системной группы: {grp.get('name')} (type={grp.get('type')})")
                continue
            if dry_run:
                logger.info(f"[DRY_RUN] Удаление группы {grp.get('name', key)}")
                continue
            res = organization.delete_group_by_id(grp['id'])
            if res.get('success'):
                logger.debug(f"Группа {grp.get('name', key)} удалена.")
            else:
                logger.error(f"Ошибка удаления группы {grp.get('name', key)}: {res.get('error')}")
                
    logger.info("--- Конец синхронизации групп ---")


if __name__ == '__main__':
    denv_path = os.path.join(os.path.dirname(__file__), '.env_ldap')
    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path, verbose=True, override=True)
    else:
        logger.error(f"Файл {denv_path} не найден!")
        sys.exit(1)

    org_id = os.environ.get('orgId')
    token = os.environ.get('token')
    if not org_id or not token:
        logger.error("Отсутствуют обязательные переменные orgId или token!")
        sys.exit(1)

    organization = API360(org_id, token)

    logger.info('Подключение к Яндекс 360...')
    try:
        test_grps = organization.get_groups_list()
        if test_grps is None:
            logger.error("Не удалось подключиться к API групп. Проверьте токен и orgId.")
            sys.exit(1)
        logger.info(f"Соединение с Яндекс 360 успешно. Найдено групп: {len(test_grps)}")
    except Exception as e:
        logger.error(f"Исключение при подключении: {e}")
        sys.exit(1)

    dry_run = os.environ.get('DRY_RUN', 'False').lower() in ['true', '1']
    if dry_run:
        logger.info('--- Режим тестового прогона включен (DRY_RUN = True)! Изменения не сохраняются! ---')

    compare_and_sync_groups(organization, dry_run=dry_run)
