#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib3
from datetime import datetime
from urllib.parse import quote

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# CONFIGURATION
# ============================================================

MAIN_NODES = [
    "HA MAIN PRIMARY IP",
    "HA MAIN SECONDARY IP"
]

DRC_NODES = [
    "HA DRC PRIMARY IP",
    "HA DRC SECONDARY IP"
]

NS_USER = "nsroot"

# Kendi sifrelerinizi buraya girin.
MAIN_PASS = r"HA MAIN IP SIFRE"
DRC_PASS = r"HA DRC IP SIFRE"


# ============================================================
# RESOURCE LMAIN
# ============================================================

PRIMARY_RESOURCES = [
    "policydataset",
    "policydataset_value_binding",

    "responderaction",
    "responderpolicy",

    "rewriteaction",
    "rewritepolicy",

    "csaction",
    "cspolicy",

    "server",
    "servicegroup",
    "service",

    "lbvserver",
    "csvserver",

    "csvserver_cspolicy_binding",

    "lbvserver_responderpolicy_binding",
    "lbvserver_rewritepolicy_binding",

    "csvserver_responderpolicy_binding",
    "csvserver_rewritepolicy_binding",

    "lbvserver_service_binding"
]


# ============================================================
# POLICY BINDING RESOURCE TYPES
# ============================================================

POLICY_BINDING_RESOURCES = [
    "lbvserver_responderpolicy_binding",
    "lbvserver_rewritepolicy_binding",
    "csvserver_responderpolicy_binding",
    "csvserver_rewritepolicy_binding"
]


# ============================================================
# LOGGING
# ============================================================

def log(message):

    print(
        "["
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        + "] "
        + message
    )


# ============================================================
# RESPONSE MESSAGE
# ============================================================

def get_response_message(res):

    try:

        data = res.json()

        if isinstance(data, dict):

            return (
                data.get("message")
                or
                data.get("errorcode")
                or
                res.text
            )

    except Exception:
        pass

    return res.text


# ============================================================
# NITRO SESSION
# ============================================================

def get_session(
    base_url,
    password
):

    url = (
        base_url
        + "/nitro/v1/config/login"
    )

    try:

        res = requests.post(
            url,
            json={
                "login": {
                    "username": NS_USER,
                    "password": password
                }
            },
            verify=False,
            timeout=5
        )

        if res.status_code in [
            200,
            201
        ]:

            try:

                session_id = (
                    res.cookies.get(
                        "NITRO_AUTH_TOKEN"
                    )
                    or
                    res.json().get(
                        "sessionid"
                    )
                )

                return session_id

            except Exception:

                return None

        log(
            "[!] Login basarisiz "
            + base_url
            + " HTTP="
            + str(res.status_code)
        )

        log(
            "    Response: "
            + str(get_response_message(res))
        )

    except Exception as e:

        log(
            "[!] Login hatasi "
            + base_url
            + ": "
            + str(e)
        )

    return None


# ============================================================
# FIND ACTIVE PRIMARY NODE
# ============================================================

def find_active_primary_node(
    node_ips,
    password,
    location_name
):

    log(
        "[*] "
        + location_name
        + " HA Cifti taraniyor..."
    )

    for ip in node_ips:

        base_url = (
            "https://"
            + ip
        )

        session_id = get_session(
            base_url,
            password
        )

        if not session_id:
            continue

        try:

            res = requests.get(
                base_url
                + "/nitro/v1/config/hanode",
                headers={
                    "Cookie":
                    "NITRO_AUTH_TOKEN="
                    + str(session_id)
                },
                verify=False,
                timeout=5
            )

            if res.status_code != 200:
                continue

            ha_nodes = res.json().get(
                "hanode",
                []
            )

            if isinstance(
                ha_nodes,
                lMAIN
            ):

                if not ha_nodes:
                    continue

                local_node = ha_nodes[0]

            else:

                local_node = ha_nodes

            state = str(
                local_node.get(
                    "state",
                    ""
                )
            ).lower()

            hastate = str(
                local_node.get(
                    "hastate",
                    ""
                )
            ).lower()

            if (
                "primary" in state
                or
                "primary" in hastate
            ):

                log(
                    "    [OK] "
                    + location_name
                    + " Aktif PRIMARY Node: "
                    + ip
                )

                return (
                    base_url,
                    session_id
                )

        except Exception as e:

            log(
                "    [!] HA kontrol hatasi "
                + ip
                + ": "
                + str(e)
            )

            continue

    return None, None


# ============================================================
# GET NORMAL RESOURCE
# ============================================================

def get_normal_resource(
    base_url,
    session_id,
    resource_type
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    url = (
        base_url
        + "/nitro/v1/config/"
        + resource_type
    )

    try:

        res = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code != 200:

            log(
                "[!] GET "
                + resource_type
                + " basarisiz. HTTP="
                + str(res.status_code)
            )

            return []

        try:

            data = res.json().get(
                resource_type,
                []
            )

        except Exception as e:

            log(
                "[!] GET "
                + resource_type
                + " JSON parse hatasi: "
                + str(e)
            )

            return []

        if isinstance(
            data,
            lMAIN
        ):

            return data

        if isinstance(
            data,
            dict
        ):

            return [data]

        return []

    except Exception as e:

        log(
            "[!] GET "
            + resource_type
            + " hatasi: "
            + str(e)
        )

        return []


# ============================================================
# GENERIC GET POLICY BINDINGS
# ============================================================

def get_policy_binding_resources(
    base_url,
    session_id,
    resource_type,
    parent_resource_type
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    parents = get_normal_resource(
        base_url,
        session_id,
        parent_resource_type
    )

    all_bindings = []

    for parent in parents:

        parent_name = parent.get(
            "name"
        )

        if not parent_name:
            continue

        url = (
            base_url
            + "/nitro/v1/config/"
            + resource_type
            + "/"
            + quote(
                str(parent_name),
                safe=""
            )
        )

        try:

            res = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=10
            )

            if res.status_code != 200:

                log(
                    "[!] "
                    + resource_type
                    + " GET basarisiz: "
                    + str(parent_name)
                    + " HTTP="
                    + str(res.status_code)
                )

                continue

            data = res.json().get(
                resource_type,
                []
            )

            if isinstance(
                data,
                lMAIN
            ):

                for item in data:

                    # Parent VServer adini koru.
                    item["name"] = (
                        item.get("name")
                        or
                        item.get(
                            parent_resource_type
                            + "name"
                        )
                        or
                        item.get(
                            parent_resource_type
                        )
                        or
                        parent_name
                    )

                    all_bindings.append(
                        item
                    )

            elif isinstance(
                data,
                dict
            ):

                data["name"] = (
                    data.get("name")
                    or
                    data.get(
                        parent_resource_type
                        + "name"
                    )
                    or
                    data.get(
                        parent_resource_type
                    )
                    or
                    parent_name
                )

                all_bindings.append(
                    data
                )

        except Exception as e:

            log(
                "[!] "
                + resource_type
                + " GET hatasi "
                + str(parent_name)
                + ": "
                + str(e)
            )

    return all_bindings


# ============================================================
# GET POLICY BINDINGS
# ============================================================

def get_lbvserver_responderpolicy_bindings(
    base_url,
    session_id
):

    return get_policy_binding_resources(
        base_url,
        session_id,
        "lbvserver_responderpolicy_binding",
        "lbvserver"
    )


def get_lbvserver_rewritepolicy_bindings(
    base_url,
    session_id
):

    return get_policy_binding_resources(
        base_url,
        session_id,
        "lbvserver_rewritepolicy_binding",
        "lbvserver"
    )


def get_csvserver_responderpolicy_bindings(
    base_url,
    session_id
):

    return get_policy_binding_resources(
        base_url,
        session_id,
        "csvserver_responderpolicy_binding",
        "csvserver"
    )


def get_csvserver_rewritepolicy_bindings(
    base_url,
    session_id
):

    return get_policy_binding_resources(
        base_url,
        session_id,
        "csvserver_rewritepolicy_binding",
        "csvserver"
    )


# ============================================================
# GET POLICY BINDINGS
# ============================================================

def get_policy_bindings(
    base_url,
    session_id,
    resource_type
):

    if resource_type == (
        "lbvserver_responderpolicy_binding"
    ):

        return get_lbvserver_responderpolicy_bindings(
            base_url,
            session_id
        )

    if resource_type == (
        "lbvserver_rewritepolicy_binding"
    ):

        return get_lbvserver_rewritepolicy_bindings(
            base_url,
            session_id
        )

    if resource_type == (
        "csvserver_responderpolicy_binding"
    ):

        return get_csvserver_responderpolicy_bindings(
            base_url,
            session_id
        )

    if resource_type == (
        "csvserver_rewritepolicy_binding"
    ):

        return get_csvserver_rewritepolicy_bindings(
            base_url,
            session_id
        )

    return []


# ============================================================
# GET POLICY DATASET VALUE BINDINGS
# ============================================================

def get_dataset_value_bindings(
    base_url,
    session_id
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    datasets = get_normal_resource(
        base_url,
        session_id,
        "policydataset"
    )

    all_bindings = []

    for dataset in datasets:

        dataset_name = dataset.get(
            "name"
        )

        if not dataset_name:
            continue

        url = (
            base_url
            + "/nitro/v1/config/"
            "policydataset_value_binding/"
            + quote(
                str(dataset_name),
                safe=""
            )
        )

        try:

            res = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=10
            )

            if res.status_code != 200:

                log(
                    "[!] Dataset binding GET basarisiz: "
                    + str(dataset_name)
                    + " HTTP="
                    + str(res.status_code)
                )

                continue

            data = res.json().get(
                "policydataset_value_binding",
                []
            )

            if isinstance(
                data,
                lMAIN
            ):

                for item in data:

                    item["name"] = (
                        item.get("name")
                        or
                        dataset_name
                    )

                    all_bindings.append(
                        item
                    )

            elif isinstance(
                data,
                dict
            ):

                data["name"] = (
                    data.get("name")
                    or
                    dataset_name
                )

                all_bindings.append(
                    data
                )

        except Exception as e:

            log(
                "[!] Dataset binding GET hatasi "
                + str(dataset_name)
                + ": "
                + str(e)
            )

    return all_bindings


# ============================================================
# GET CSV SERVER CS POLICY BINDINGS
# ============================================================

def get_csvserver_cspolicy_bindings(
    base_url,
    session_id
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    csvservers = get_normal_resource(
        base_url,
        session_id,
        "csvserver"
    )

    all_bindings = []

    for csvserver in csvservers:

        csvserver_name = csvserver.get(
            "name"
        )

        if not csvserver_name:
            continue

        url = (
            base_url
            + "/nitro/v1/config/"
            "csvserver_cspolicy_binding/"
            + quote(
                str(csvserver_name),
                safe=""
            )
        )

        try:

            res = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=10
            )

            if res.status_code != 200:

                log(
                    "[!] CSV binding GET basarisiz: "
                    + str(csvserver_name)
                    + " HTTP="
                    + str(res.status_code)
                )

                continue

            data = res.json().get(
                "csvserver_cspolicy_binding",
                []
            )

            if isinstance(
                data,
                lMAIN
            ):

                for item in data:

                    item["name"] = (
                        item.get("name")
                        or
                        csvserver_name
                    )

                    all_bindings.append(
                        item
                    )

            elif isinstance(
                data,
                dict
            ):

                data["name"] = (
                    data.get("name")
                    or
                    csvserver_name
                )

                all_bindings.append(
                    data
                )

        except Exception as e:

            log(
                "[!] CSV binding GET hatasi "
                + str(csvserver_name)
                + ": "
                + str(e)
            )

    return all_bindings


# ============================================================
# GET LB VSERVER SERVICE BINDINGS
# ============================================================

def get_lbvserver_service_bindings(
    base_url,
    session_id
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    lbvservers = get_normal_resource(
        base_url,
        session_id,
        "lbvserver"
    )

    all_bindings = []

    for lbvserver in lbvservers:

        lb_name = lbvserver.get(
            "name"
        )

        if not lb_name:
            continue

        url = (
            base_url
            + "/nitro/v1/config/"
            "lbvserver_service_binding/"
            + quote(
                str(lb_name),
                safe=""
            )
        )

        try:

            res = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=10
            )

            if res.status_code != 200:

                log(
                    "[!] LB-Service binding GET basarisiz: "
                    + str(lb_name)
                    + " HTTP="
                    + str(res.status_code)
                )

                continue

            data = res.json().get(
                "lbvserver_service_binding",
                []
            )

            if isinstance(
                data,
                lMAIN
            ):

                for item in data:

                    item["name"] = (
                        item.get("name")
                        or
                        lb_name
                    )

                    all_bindings.append(
                        item
                    )

            elif isinstance(
                data,
                dict
            ):

                data["name"] = (
                    data.get("name")
                    or
                    lb_name
                )

                all_bindings.append(
                    data
                )

        except Exception as e:

            log(
                "[!] LB-Service binding GET hatasi "
                + str(lb_name)
                + ": "
                + str(e)
            )

    return all_bindings


# ============================================================
# GET RESOURCES
# ============================================================

def get_resources(
    base_url,
    session_id,
    resource_type
):

    if resource_type == (
        "policydataset_value_binding"
    ):

        return get_dataset_value_bindings(
            base_url,
            session_id
        )

    if resource_type == (
        "csvserver_cspolicy_binding"
    ):

        return get_csvserver_cspolicy_bindings(
            base_url,
            session_id
        )

    if resource_type == (
        "lbvserver_service_binding"
    ):

        return get_lbvserver_service_bindings(
            base_url,
            session_id
        )

    if resource_type in POLICY_BINDING_RESOURCES:

        return get_policy_bindings(
            base_url,
            session_id,
            resource_type
        )

    return get_normal_resource(
        base_url,
        session_id,
        resource_type
    )


# ============================================================
# RESOURCE KEY
# ============================================================

def get_resource_key(
    r_type,
    item
):

    if r_type in [
        "server",
        "lbvserver",
        "csvserver",
        "responderaction",
        "responderpolicy",
        "rewriteaction",
        "rewritepolicy",
        "csaction",
        "cspolicy",
        "policydataset"
    ]:

        return (
            item.get("name")
            or
            item.get("policyname")
        )

    elif r_type == "service":

        return (
            item.get("name")
            or
            item.get("servicename")
        )

    elif r_type == "servicegroup":

        return item.get(
            "servicegroupname"
        )

    elif r_type == (
        "policydataset_value_binding"
    ):

        return (
            str(
                item.get(
                    "name",
                    ""
                )
            )
            + "|"
            + str(
                item.get(
                    "value",
                    ""
                )
            )
            + "|"
            + str(
                item.get(
                    "index",
                    ""
                )
            )
        )

    elif r_type == (
        "lbvserver_service_binding"
    ):

        lb_name = (
            item.get("name")
            or
            item.get("lbvservername")
            or
            item.get("lbvserver")
        )

        service_name = (
            item.get("servicename")
            or
            item.get("service")
        )

        if not lb_name or not service_name:
            return None

        return (
            str(lb_name)
            + "|"
            + str(service_name)
        )

    elif r_type == (
        "csvserver_cspolicy_binding"
    ):

        csvserver_name = (
            item.get("name")
            or
            item.get("csvservername")
            or
            item.get("csvserver")
        )

        policy_name = (
            item.get("policyname")
            or
            item.get("policy")
        )

        priority = (
            item.get("priority")
            or
            ""
        )

        if not csvserver_name or not policy_name:
            return None

        return (
            str(csvserver_name)
            + "|"
            + str(policy_name)
            + "|"
            + str(priority)
        )

    elif r_type in [
        "lbvserver_responderpolicy_binding",
        "lbvserver_rewritepolicy_binding",
        "csvserver_responderpolicy_binding",
        "csvserver_rewritepolicy_binding"
    ]:

        if r_type.startswith(
            "lbvserver_"
        ):

            parent_name = (
                item.get("name")
                or
                item.get("lbvservername")
                or
                item.get("lbvserver")
            )

        else:

            parent_name = (
                item.get("name")
                or
                item.get("csvservername")
                or
                item.get("csvserver")
            )

        policy_name = (
            item.get("policyname")
            or
            item.get("policy")
            or
            item.get("responderpolicyname")
            or
            item.get("rewritepolicyname")
            or
            item.get("responderpolicy")
            or
            item.get("rewritepolicy")
        )

        if not parent_name or not policy_name:
            return None

        priority = (
            item.get("priority")
            or
            ""
        )

        return (
            str(parent_name)
            + "|"
            + str(policy_name)
            + "|"
            + str(priority)
        )

    return item.get(
        "name"
    )


# ============================================================
# PREPARE PAYLOAD
# ============================================================

def prepare_payload(
    resource_type,
    payload_data
):

    ALLOWED_FIELDS = {

        "server": [
            "name",
            "ipaddress",
            "domain",
            "state",
            "comment"
        ],

        "service": [
            "name",
            "servicename",
            "servername",
            "servicetype",
            "port",
            "state",
            "comment"
        ],

        "servicegroup": [
            "servicegroupname",
            "servicetype",
            "port",
            "state",
            "comment"
        ],

        "lbvserver": [
            "name",
            "servicetype",
            "ipv46",
            "port",
            "persMAINenceType",
            "timeout",
            "lbmethod",
            "comment"
        ],

        "csvserver": [
            "name",
            "servicetype",
            "ipv46",
            "port",
            "comment",
            "state"
        ],

        "responderpolicy": [
            "name",
            "rule",
            "action",
            "comment"
        ],

        "responderaction": [
            "name",
            "type",
            "target",
            "comment"
        ],

        "rewritepolicy": [
            "name",
            "rule",
            "action",
            "comment"
        ],

        "rewriteaction": [
            "name",
            "type",
            "target",
            "comment"
        ],

        "cspolicy": [
            "name",
            "policyname",
            "rule",
            "action",
            "targetlbvserver",
            "comment"
        ],

        "csaction": [
            "name",
            "targetlbvserver",
            "comment"
        ],

        "policydataset": [
            "name",
            "type",
            "comment",
            "patsetfile",
            "dynamic",
            "indextype"
        ],

        "policydataset_value_binding": [
            "name",
            "value",
            "index",
            "endrange",
            "comment"
        ],

        "csvserver_cspolicy_binding": [
            "name",
            "csvservername",
            "csvserver",
            "policyname",
            "policy",
            "priority",
            "targetlbvserver",
            "gotopriorityexpression",
            "invoke",
            "type",
            "labeltype",
            "labelname",
            "state",
            "comment"
        ],

        "lbvserver_service_binding": [
            "name",
            "servicename",
            "weight",
            "monitor_name",
            "customserverid",
            "hashid",
            "state",
            "comment"
        ],

        "lbvserver_responderpolicy_binding": [
            "name",
            "lbvservername",
            "lbvserver",
            "policyname",
            "policy",
            "priority",
            "gotopriorityexpression",
            "invoke",
            "state",
            "labeltype",
            "labelname",
            "comment"
        ],

        "lbvserver_rewritepolicy_binding": [
            "name",
            "lbvservername",
            "lbvserver",
            "policyname",
            "policy",
            "priority",
            "gotopriorityexpression",
            "invoke",
            "state",
            "labeltype",
            "labelname",
            "comment"
        ],

        "csvserver_responderpolicy_binding": [
            "name",
            "csvservername",
            "csvserver",
            "policyname",
            "policy",
            "priority",
            "gotopriorityexpression",
            "invoke",
            "state",
            "labeltype",
            "labelname",
            "comment"
        ],

        "csvserver_rewritepolicy_binding": [
            "name",
            "csvservername",
            "csvserver",
            "policyname",
            "policy",
            "priority",
            "gotopriorityexpression",
            "invoke",
            "state",
            "labeltype",
            "labelname",
            "comment"
        ]
    }

    allowed = ALLOWED_FIELDS.get(
        resource_type,
        []
    )

    if not allowed:

        return payload_data.copy()

    clean = {
        k: v
        for k, v in payload_data.items()
        if k in allowed
        and v is not None
    }

    # --------------------------------------------------------
    # SERVICE
    # --------------------------------------------------------

    if resource_type == "service":

        clean["name"] = (
            clean.get("name")
            or
            clean.get("servicename")
        )

        clean.pop(
            "servicename",
            None
        )

        clean["servername"] = (
            clean.get("servername")
            or
            clean.get("name")
        )

    # --------------------------------------------------------
    # CSPOLICY
    # --------------------------------------------------------

    if resource_type == "cspolicy":

        clean["policyname"] = (
            clean.get("policyname")
            or
            clean.get("name")
        )

        clean.pop(
            "name",
            None
        )

    # --------------------------------------------------------
    # POLICY BINDINGS
    # --------------------------------------------------------

    if resource_type in POLICY_BINDING_RESOURCES:

        if resource_type.startswith(
            "lbvserver_"
        ):

            parent_name = (
                payload_data.get(
                    "lbvservername"
                )
                or
                payload_data.get(
                    "lbvserver"
                )
                or
                payload_data.get(
                    "name"
                )
            )

        else:

            parent_name = (
                payload_data.get(
                    "csvservername"
                )
                or
                payload_data.get(
                    "csvserver"
                )
                or
                payload_data.get(
                    "name"
                )
            )

        policy_name = (
            payload_data.get(
                "policyname"
            )
            or
            payload_data.get(
                "policy"
            )
            or
            payload_data.get(
                "responderpolicyname"
            )
            or
            payload_data.get(
                "rewritepolicyname"
            )
        )

        # ----------------------------------------------------
        # KRITIK FIX
        #
        # Binding POST/PUT body icinde name zorunlu.
        # name = parent VServer / CSVServer adi.
        # ----------------------------------------------------

        if parent_name:
            clean["name"] = parent_name

        if policy_name:
            clean["policyname"] = policy_name

        # Parent alanlarini temizle.
        clean.pop(
            "csvservername",
            None
        )

        clean.pop(
            "csvserver",
            None
        )

        clean.pop(
            "lbvservername",
            None
        )

        clean.pop(
            "lbvserver",
            None
        )

        # Alternatif policy alanlarini temizle.
        clean.pop(
            "policy",
            None
        )

        clean.pop(
            "responderpolicyname",
            None
        )

        clean.pop(
            "rewritepolicyname",
            None
        )

    return clean


# ============================================================
# CREATE POLICY BINDING
# ============================================================

def create_policy_binding(
    base_url,
    session_id,
    r_type,
    item
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    # --------------------------------------------------------
    # PARENT VSERVER
    # --------------------------------------------------------

    if r_type.startswith(
        "lbvserver_"
    ):

        parent_name = (
            item.get("lbvservername")
            or
            item.get("lbvserver")
            or
            item.get("name")
        )

    else:

        parent_name = (
            item.get("csvservername")
            or
            item.get("csvserver")
            or
            item.get("name")
        )

    if not parent_name:

        return (
            False,
            "Binding parent VServer adi bulunamadi"
        )

    # --------------------------------------------------------
    # POLICY NAME
    # --------------------------------------------------------

    policy_name = (
        item.get("policyname")
        or
        item.get("policy")
        or
        item.get("responderpolicyname")
        or
        item.get("rewritepolicyname")
    )

    if not policy_name:

        return (
            False,
            "Binding policy adi bulunamadi"
        )

    # --------------------------------------------------------
    # PAYLOAD
    # --------------------------------------------------------

    payload = prepare_payload(
        r_type,
        item
    )

    # --------------------------------------------------------
    # KRITIK FIX
    #
    # name kesinlikle payload icinde olacak.
    # name = parent VServer.
    # --------------------------------------------------------

    payload["name"] = parent_name
    payload["policyname"] = policy_name

    # Parent alternatif alanlarini temizle.
    payload.pop(
        "csvservername",
        None
    )

    payload.pop(
        "csvserver",
        None
    )

    payload.pop(
        "lbvservername",
        None
    )

    payload.pop(
        "lbvserver",
        None
    )

    # Alternatif policy alanlarini temizle.
    payload.pop(
        "policy",
        None
    )

    payload.pop(
        "responderpolicyname",
        None
    )

    payload.pop(
        "rewritepolicyname",
        None
    )

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    url = (
        base_url
        + "/nitro/v1/config/"
        + r_type
        + "/"
        + quote(
            str(parent_name),
            safe=""
        )
    )

    log(
        "        [DEBUG] Binding POST: "
        + r_type
        + " / "
        + str(parent_name)
        + " / "
        + str(policy_name)
    )

    log(
        "        [DEBUG] Binding payload: "
        + str(payload)
    )

    try:

        res = requests.post(
            url,
            json={
                r_type:
                payload
            },
            headers=headers,
            verify=False,
            timeout=10
        )

    except Exception as e:

        return (
            False,
            str(e)
        )

    if res.status_code in [
        200,
        201,
        204
    ]:

        return (
            True,
            "Policy binding eklendi"
        )

    if (
        "already exMAINs"
        in res.text.lower()
    ):

        return (
            True,
            "Zaten mevcut"
        )

    return (
        False,
        get_response_message(res)
    )


# ============================================================
# CREATE RESOURCE
# ============================================================

def create_resource(
    base_url,
    session_id,
    r_type,
    item
):

    if r_type in POLICY_BINDING_RESOURCES:

        return create_policy_binding(
            base_url,
            session_id,
            r_type,
            item
        )

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    payload = prepare_payload(
        r_type,
        item
    )

    # --------------------------------------------------------
    # CSV SERVER CS POLICY BINDING
    # --------------------------------------------------------

    if r_type == (
        "csvserver_cspolicy_binding"
    ):

        csvserver_name = (
            item.get("name")
            or
            item.get("csvservername")
            or
            item.get("csvserver")
        )

        if not csvserver_name:

            return (
                False,
                "CSVServer adi bulunamadi"
            )

        policy_name = (
            item.get("policyname")
            or
            item.get("policy")
        )

        if not policy_name:

            return (
                False,
                "CS Policy adi bulunamadi"
            )

        # ----------------------------------------------------
        # KRITIK FIX
        #
        # csvserver_cspolicy_binding icin de
        # name zorunlu.
        # ----------------------------------------------------

        payload["name"] = csvserver_name
        payload["policyname"] = policy_name

        payload.pop(
            "csvservername",
            None
        )

        payload.pop(
            "csvserver",
            None
        )

        payload.pop(
            "policy",
            None
        )

        url = (
            base_url
            + "/nitro/v1/config/"
            "csvserver_cspolicy_binding/"
            + quote(
                str(csvserver_name),
                safe=""
            )
        )

        log(
            "        [DEBUG] CS Policy Binding POST: "
            + str(csvserver_name)
            + " / "
            + str(policy_name)
        )

        log(
            "        [DEBUG] CS Binding payload: "
            + str(payload)
        )

        try:

            res = requests.post(
                url,
                json={
                    "csvserver_cspolicy_binding":
                    payload
                },
                headers=headers,
                verify=False,
                timeout=10
            )

        except Exception as e:

            return False, str(e)

    # --------------------------------------------------------
    # DATASET VALUE BINDING
    # --------------------------------------------------------

    elif r_type == (
        "policydataset_value_binding"
    ):

        dataset_name = item.get(
            "name"
        )

        if not dataset_name:

            return (
                False,
                "Dataset adi bulunamadi"
            )

        url = (
            base_url
            + "/nitro/v1/config/"
            "policydataset_value_binding/"
            + quote(
                str(dataset_name),
                safe=""
            )
        )

        try:

            res = requests.put(
                url,
                json={
                    "policydataset_value_binding":
                    payload
                },
                headers=headers,
                verify=False,
                timeout=10
            )

        except Exception as e:

            return False, str(e)

    # --------------------------------------------------------
    # NORMAL RESOURCE
    # --------------------------------------------------------

    else:

        url = (
            base_url
            + "/nitro/v1/config/"
            + r_type
        )

        try:

            res = requests.post(
                url,
                json={
                    r_type:
                    payload
                },
                headers=headers,
                verify=False,
                timeout=10
            )

        except Exception as e:

            return False, str(e)

    if res.status_code in [
        200,
        201,
        204
    ]:

        return (
            True,
            "Basarili"
        )

    if (
        "already exMAINs"
        in res.text.lower()
    ):

        return (
            True,
            "Zaten mevcut"
        )

    return (
        False,
        get_response_message(res)
    )


# ============================================================
# UPDATE LB SERVICE BINDING
# ============================================================

def update_lbvserver_service_binding(
    base_url,
    session_id,
    item
):

    lb_name = (
        item.get("name")
        or
        item.get("lbvservername")
        or
        item.get("lbvserver")
    )

    service_name = (
        item.get("servicename")
        or
        item.get("service")
    )

    if not lb_name:

        return (
            False,
            "LB-Service binding LB name eksik"
        )

    if not service_name:

        return (
            False,
            "LB-Service binding service name eksik"
        )

    url = (
        base_url
        + "/nitro/v1/config/"
        "lbvserver_service_binding/"
        + quote(
            str(lb_name),
            safe=""
        )
        + "?args=servicename:"
        + quote(
            str(service_name),
            safe=""
        )
    )

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    payload = prepare_payload(
        "lbvserver_service_binding",
        item
    )

    # Binding icin name zorunlu.
    payload["name"] = lb_name

    payload.pop(
        "lbvservername",
        None
    )

    payload.pop(
        "lbvserver",
        None
    )

    payload["servicename"] = service_name

    try:

        res = requests.put(
            url,
            json={
                "lbvserver_service_binding":
                payload
            },
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "Binding guncellendi"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# UPDATE POLICY BINDING
# ============================================================

def update_policy_binding(
    base_url,
    session_id,
    r_type,
    item
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    if r_type.startswith(
        "lbvserver_"
    ):

        parent_name = (
            item.get("lbvservername")
            or
            item.get("lbvserver")
            or
            item.get("name")
        )

    else:

        parent_name = (
            item.get("csvservername")
            or
            item.get("csvserver")
            or
            item.get("name")
        )

    policy_name = (
        item.get("policyname")
        or
        item.get("policy")
        or
        item.get("responderpolicyname")
        or
        item.get("rewritepolicyname")
    )

    priority = item.get(
        "priority"
    )

    if not parent_name:

        return (
            False,
            "Binding parent adi eksik"
        )

    if not policy_name:

        return (
            False,
            "Binding policy adi eksik"
        )

    url = (
        base_url
        + "/nitro/v1/config/"
        + r_type
        + "/"
        + quote(
            str(parent_name),
            safe=""
        )
        + "?args=policyname:"
        + quote(
            str(policy_name),
            safe=""
        )
    )

    if priority is not None:

        url += (
            ",priority:"
            + quote(
                str(priority),
                safe=""
            )
        )

    payload = prepare_payload(
        r_type,
        item
    )

    # --------------------------------------------------------
    # KRITIK FIX
    #
    # PUT body icinde name ve policyname olacak.
    # --------------------------------------------------------

    payload["name"] = parent_name
    payload["policyname"] = policy_name

    payload.pop(
        "csvservername",
        None
    )

    payload.pop(
        "csvserver",
        None
    )

    payload.pop(
        "lbvservername",
        None
    )

    payload.pop(
        "lbvserver",
        None
    )

    payload.pop(
        "policy",
        None
    )

    payload.pop(
        "responderpolicyname",
        None
    )

    payload.pop(
        "rewritepolicyname",
        None
    )

    try:

        res = requests.put(
            url,
            json={
                r_type:
                payload
            },
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "Policy binding guncellendi"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# UPDATE RESOURCE
# ============================================================

def update_resource(
    base_url,
    session_id,
    r_type,
    key,
    item
):

    if r_type == (
        "lbvserver_service_binding"
    ):

        return update_lbvserver_service_binding(
            base_url,
            session_id,
            item
        )

    if r_type in POLICY_BINDING_RESOURCES:

        return update_policy_binding(
            base_url,
            session_id,
            r_type,
            item
        )

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    if r_type == "cspolicy":

        url = (
            base_url
            + "/nitro/v1/config/"
            "cspolicy/"
            + quote(
                str(key),
                safe=""
            )
            + "?args=policyName:"
            + quote(
                str(key),
                safe=""
            )
        )

    else:

        url = (
            base_url
            + "/nitro/v1/config/"
            + r_type
            + "/"
            + quote(
                str(key),
                safe=""
            )
        )

    payload = prepare_payload(
        r_type,
        item
    )

    try:

        res = requests.put(
            url,
            json={
                r_type:
                payload
            },
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "Guncellendi"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# DELETE DATASET VALUE BINDING
# ============================================================

def delete_dataset_value_binding(
    base_url,
    session_id,
    item
):

    dataset_name = item.get(
        "name"
    )

    value = item.get(
        "value"
    )

    index = item.get(
        "index"
    )

    if not dataset_name:

        return (
            False,
            "Dataset name eksik"
        )

    if value is None:

        return (
            False,
            "Dataset value eksik"
        )

    url = (
        base_url
        + "/nitro/v1/config/"
        "policydataset_value_binding/"
        + quote(
            str(dataset_name),
            safe=""
        )
        + "?args=value:"
        + quote(
            str(value),
            safe=""
        )
    )

    if index is not None:

        url += (
            ",index:"
            + quote(
                str(index),
                safe=""
            )
        )

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    try:

        res = requests.delete(
            url,
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "Dataset binding silindi"
            )

        response_text = (
            res.text or ""
        ).lower()

        if (
            "no such resource"
            in response_text
            or
            "does not exMAIN"
            in response_text
        ):

            return (
                True,
                "Zaten mevcut degil"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# DELETE LB SERVICE BINDING
# ============================================================

def delete_lbvserver_service_binding(
    base_url,
    session_id,
    item
):

    lb_name = (
        item.get("name")
        or
        item.get("lbvservername")
        or
        item.get("lbvserver")
    )

    service_name = (
        item.get("servicename")
        or
        item.get("service")
    )

    if not lb_name:

        return (
            False,
            "LB VServer adi eksik"
        )

    if not service_name:

        return (
            False,
            "Service adi eksik"
        )

    url = (
        base_url
        + "/nitro/v1/config/"
        "lbvserver_service_binding/"
        + quote(
            str(lb_name),
            safe=""
        )
        + "?args=servicename:"
        + quote(
            str(service_name),
            safe=""
        )
    )

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    try:

        res = requests.delete(
            url,
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "LB-Service binding silindi"
            )

        response_text = (
            res.text or ""
        ).lower()

        if (
            "no such resource"
            in response_text
            or
            "does not exMAIN"
            in response_text
        ):

            return (
                True,
                "Zaten mevcut degil"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# DELETE CS POLICY BINDING
# ============================================================

def delete_cs_policy_binding(
    base_url,
    session_id,
    csvserver_name,
    policy_name,
    priority=None
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    url = (
        base_url
        + "/nitro/v1/config/"
        "csvserver_cspolicy_binding/"
        + quote(
            str(csvserver_name),
            safe=""
        )
        + "?args=policyname:"
        + quote(
            str(policy_name),
            safe=""
        )
    )

    if priority is not None:

        url += (
            ",priority:"
            + quote(
                str(priority),
                safe=""
            )
        )

    try:

        res = requests.delete(
            url,
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "Binding silindi"
            )

        response_text = (
            res.text or ""
        ).lower()

        if (
            "no such resource"
            in response_text
            or
            "does not exMAIN"
            in response_text
        ):

            return (
                True,
                "Zaten mevcut degil"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# DELETE POLICY BINDING
# ============================================================

def delete_policy_binding(
    base_url,
    session_id,
    r_type,
    item
):

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    if r_type.startswith(
        "lbvserver_"
    ):

        parent_name = (
            item.get("lbvservername")
            or
            item.get("lbvserver")
            or
            item.get("name")
        )

    else:

        parent_name = (
            item.get("csvservername")
            or
            item.get("csvserver")
            or
            item.get("name")
        )

    policy_name = (
        item.get("policyname")
        or
        item.get("policy")
        or
        item.get("responderpolicyname")
        or
        item.get("rewritepolicyname")
    )

    priority = item.get(
        "priority"
    )

    if not parent_name:

        return (
            False,
            "Binding parent adi eksik"
        )

    if not policy_name:

        return (
            False,
            "Binding policy adi eksik"
        )

    url = (
        base_url
        + "/nitro/v1/config/"
        + r_type
        + "/"
        + quote(
            str(parent_name),
            safe=""
        )
        + "?args=policyname:"
        + quote(
            str(policy_name),
            safe=""
        )
    )

    if priority is not None:

        url += (
            ",priority:"
            + quote(
                str(priority),
                safe=""
            )
        )

    try:

        res = requests.delete(
            url,
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "Policy binding silindi"
            )

        response_text = (
            res.text or ""
        ).lower()

        if (
            "no such resource"
            in response_text
            or
            "does not exMAIN"
            in response_text
        ):

            return (
                True,
                "Zaten mevcut degil"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# DELETE RESOURCE
# ============================================================

def delete_resource(
    base_url,
    session_id,
    r_type,
    key
):

    if r_type == (
        "policydataset_value_binding"
    ):

        if isinstance(
            key,
            dict
        ):

            return delete_dataset_value_binding(
                base_url,
                session_id,
                key
            )

        return (
            False,
            "Dataset binding silme icin item gerekli"
        )

    if r_type == (
        "lbvserver_service_binding"
    ):

        if isinstance(
            key,
            dict
        ):

            return delete_lbvserver_service_binding(
                base_url,
                session_id,
                key
            )

        return (
            False,
            "LB-Service binding silme icin item gerekli"
        )

    if r_type == (
        "csvserver_cspolicy_binding"
    ):

        if isinstance(
            key,
            dict
        ):

            csvserver_name = (
                key.get("name")
                or
                key.get("csvservername")
                or
                key.get("csvserver")
            )

            policy_name = (
                key.get("policyname")
                or
                key.get("policy")
            )

            priority = key.get(
                "priority"
            )

            if not csvserver_name:

                return (
                    False,
                    "CSVServer adi eksik"
                )

            if not policy_name:

                return (
                    False,
                    "CS Policy adi eksik"
                )

            return delete_cs_policy_binding(
                base_url,
                session_id,
                csvserver_name,
                policy_name,
                priority
            )

        return (
            False,
            "CS binding silme icin item gerekli"
        )

    if r_type in POLICY_BINDING_RESOURCES:

        if isinstance(
            key,
            dict
        ):

            return delete_policy_binding(
                base_url,
                session_id,
                r_type,
                key
            )

        return (
            False,
            "Policy binding silme icin item gerekli"
        )

    if r_type == "cspolicy":

        url = (
            base_url
            + "/nitro/v1/config/"
            "cspolicy/"
            + quote(
                str(key),
                safe=""
            )
            + "?args=policyName:"
            + quote(
                str(key),
                safe=""
            )
        )

    else:

        url = (
            base_url
            + "/nitro/v1/config/"
            + r_type
            + "/"
            + quote(
                str(key),
                safe=""
            )
        )

    headers = {
        "Cookie":
        "NITRO_AUTH_TOKEN="
        + str(session_id),

        "Content-Type":
        "application/json"
    }

    try:

        res = requests.delete(
            url,
            headers=headers,
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201,
            204
        ]:

            return (
                True,
                "Silindi"
            )

        response_text = (
            res.text or ""
        ).lower()

        if (
            "no such resource"
            in response_text
            or
            "does not exMAIN"
            in response_text
        ):

            return (
                True,
                "Zaten mevcut degil"
            )

        return (
            False,
            get_response_message(res)
        )

    except Exception as e:

        return (
            False,
            str(e)
        )


# ============================================================
# CLEAN CS POLICIES FOR LB
# ============================================================

def cleanup_cs_policies_for_lb(
    base_url,
    session_id,
    target_name
):

    log(
        "    [*] CS Policy baglantilari "
        "kontrol ediliyor: "
        + target_name
    )

    policies = get_resources(
        base_url,
        session_id,
        "cspolicy"
    )

    bindings = get_resources(
        base_url,
        session_id,
        "csvserver_cspolicy_binding"
    )

    removed_bindings = 0

    for policy in policies:

        policy_name = policy.get(
            "name"
        )

        policy_target = policy.get(
            "targetlbvserver"
        )

        if not policy_name:
            continue

        if policy_target != target_name:
            continue

        log(
            "    [!] Target LB bulundu: "
            + policy_name
            + " -> "
            + target_name
        )

        for binding in bindings:

            binding_policy = (
                binding.get(
                    "policyname"
                )
                or
                binding.get(
                    "policy"
                )
            )

            csvserver_name = (
                binding.get(
                    "name"
                )
                or
                binding.get(
                    "csvservername"
                )
                or
                binding.get(
                    "csvserver"
                )
            )

            priority = binding.get(
                "priority"
            )

            if (
                binding_policy
                != policy_name
            ):

                continue

            if not csvserver_name:
                continue

            log(
                "        [-] CS Binding siliniyor: "
                + csvserver_name
                + " / "
                + policy_name
            )

            ok, msg = delete_cs_policy_binding(
                base_url,
                session_id,
                csvserver_name,
                policy_name,
                priority
            )

            if ok:

                log(
                    "            [OK] Binding silindi."
                )

                removed_bindings += 1

            else:

                log(
                    "            [!] Binding silinemedi: "
                    + str(msg)
                )

    for binding in bindings:

        binding_policy = (
            binding.get(
                "policyname"
            )
            or
            binding.get(
                "policy"
            )
        )

        csvserver_name = (
            binding.get(
                "name"
            )
            or
            binding.get(
                "csvservername"
            )
            or
            binding.get(
                "csvserver"
            )
        )

        binding_target = (
            binding.get(
                "targetlbvserver"
            )
            or
            binding.get(
                "lbvserver"
            )
        )

        priority = binding.get(
            "priority"
        )

        if binding_target != target_name:
            continue

        if (
            not csvserver_name
            or
            not binding_policy
        ):

            continue

        ok, msg = delete_cs_policy_binding(
            base_url,
            session_id,
            csvserver_name,
            binding_policy,
            priority
        )

        if ok:

            log(
                "        [OK] Target LB binding kaldirildi."
            )

            removed_bindings += 1

        else:

            log(
                "        [!] Target LB binding "
                "kaldirilamadi: "
                + str(msg)
            )

    for policy in policies:

        policy_name = policy.get(
            "name"
        )

        policy_target = policy.get(
            "targetlbvserver"
        )

        if (
            policy_name
            and
            policy_target == target_name
        ):

            log(
                "    [-] Iliskili CS Policy siliniyor: "
                + policy_name
            )

            ok, msg = delete_resource(
                base_url,
                session_id,
                "cspolicy",
                policy_name
            )

            if ok:

                log(
                    "        [OK] CS Policy silindi."
                )

            else:

                log(
                    "        [!] CS Policy silinemedi: "
                    + str(msg)
                )

    return removed_bindings


# ============================================================
# CLEAN CR POLICIES FOR LB
# ============================================================

def cleanup_cr_policies_for_lb(
    base_url,
    session_id,
    target_name
):

    log(
        "    [*] CR Policy baglantilari "
        "kontrol ediliyor: "
        + target_name
    )

    # Resource PRIMARY_RESOURCES icinde yoksa
    # mevcut configuration'dan yine de okumayi dene.
    bindings = get_normal_resource(
        base_url,
        session_id,
        "crvserver_crpolicy_binding"
    )

    removed = 0

    for binding in bindings:

        cr_name = (
            binding.get(
                "name"
            )
            or
            binding.get(
                "crvserver"
            )
            or
            binding.get(
                "crvservername"
            )
        )

        policy_name = (
            binding.get(
                "policyname"
            )
            or
            binding.get(
                "policy"
            )
        )

        target_lb = (
            binding.get(
                "targetlbvserver"
            )
            or
            binding.get(
                "lbvserver"
            )
        )

        if target_lb != target_name:
            continue

        if (
            not cr_name
            or
            not policy_name
        ):

            continue

        headers = {
            "Cookie":
            "NITRO_AUTH_TOKEN="
            + str(session_id),

            "Content-Type":
            "application/json"
        }

        url = (
            base_url
            + "/nitro/v1/config/"
            "crvserver_crpolicy_binding/"
            + quote(
                str(cr_name),
                safe=""
            )
            + "?args=policyname:"
            + quote(
                str(policy_name),
                safe=""
            )
        )

        try:

            res = requests.delete(
                url,
                headers=headers,
                verify=False,
                timeout=10
            )

            if res.status_code in [
                200,
                201,
                204
            ]:

                log(
                    "        [OK] CR Binding silindi."
                )

                removed += 1

            else:

                log(
                    "        [!] CR Binding silinemedi: "
                    + str(get_response_message(res))
                )

        except Exception as e:

            log(
                "        [!] CR Binding hatasi: "
                + str(e)
            )

    return removed


# ============================================================
# COMPLETE DEPENDENCY CLEANUP
# ============================================================

def force_unbind_and_clean_target(
    base_url,
    session_id,
    target_name
):

    log(
        "    [*] Dependency cleanup basliyor: "
        + target_name
    )

    cleanup_cs_policies_for_lb(
        base_url,
        session_id,
        target_name
    )

    cleanup_cr_policies_for_lb(
        base_url,
        session_id,
        target_name
    )

    log(
        "    [OK] Dependency cleanup tamamlandi: "
        + target_name
    )


# ============================================================
# RESOURCE EXMAINS
# ============================================================

def resource_exMAINs(
    base_url,
    session_id,
    resource_type,
    key
):

    resources = get_resources(
        base_url,
        session_id,
        resource_type
    )

    for item in resources:

        item_key = get_resource_key(
            resource_type,
            item
        )

        if item_key == key:

            return True

    return False


# ============================================================
# DELETE ORPHAN RESOURCE
# ============================================================

def delete_orphan_resource(
    base_url,
    session_id,
    r_type,
    key
):

    if r_type == "lbvserver":

        log(
            "    [!] LB VServer dependency "
            "cleanup yapiliyor: "
            + str(key)
        )

        force_unbind_and_clean_target(
            base_url,
            session_id,
            key
        )

    elif r_type == "csvserver":

        log(
            "    [!] CS VServer dependency "
            "cleanup yapiliyor: "
            + str(key)
        )

    display_key = key

    if r_type == (
        "policydataset_value_binding"
    ):

        display_key = (
            str(
                key.get(
                    "name",
                    ""
                )
            )
            + " / "
            + str(
                key.get(
                    "value",
                    ""
                )
            )
            + " / index="
            + str(
                key.get(
                    "index",
                    ""
                )
            )
        )

    elif r_type == (
        "lbvserver_service_binding"
    ):

        display_key = (
            str(
                key.get(
                    "name",
                    ""
                )
            )
            + " / "
            + str(
                key.get(
                    "servicename",
                    ""
                )
            )
        )

    elif r_type == (
        "csvserver_cspolicy_binding"
    ):

        display_key = (
            str(
                key.get(
                    "name",
                    ""
                )
            )
            + " / "
            + str(
                key.get(
                    "policyname",
                    ""
                )
            )
            + " / priority="
            + str(
                key.get(
                    "priority",
                    ""
                )
            )
        )

    elif r_type in POLICY_BINDING_RESOURCES:

        parent_name = (
            key.get("lbvservername")
            or
            key.get("lbvserver")
            or
            key.get("csvservername")
            or
            key.get("csvserver")
            or
            key.get("name")
            or
            ""
        )

        policy_name = (
            key.get("policyname")
            or
            key.get("policy")
            or
            ""
        )

        priority = (
            key.get("priority")
            or
            ""
        )

        display_key = (
            str(parent_name)
            + " / "
            + str(policy_name)
            + " / priority="
            + str(priority)
        )

    log(
        "    [-] ["
        + r_type
        + "] Siliniyor: "
        + str(display_key)
    )

    ok, msg = delete_resource(
        base_url,
        session_id,
        r_type,
        key
    )

    if ok:

        log(
            "        [OK] Silindi."
        )

        return True

    if (
        r_type == "lbvserver"
        and
        (
            "referred"
            in str(msg).lower()
            or
            "binding"
            in str(msg).lower()
            or
            "policy"
            in str(msg).lower()
        )
    ):

        log(
            "        [!] LB VServer hala "
            "bir yere referansli."
        )

        log(
            "        [*] Dependency cleanup "
            "ikinci kez calMAINiriliyor..."
        )

        force_unbind_and_clean_target(
            base_url,
            session_id,
            key
        )

        ok, msg = delete_resource(
            base_url,
            session_id,
            r_type,
            key
        )

        if ok:

            log(
                "        [OK] Ikinci denemede silindi."
            )

            return True

    log(
        "        [-] Silme Hatasi: "
        + str(msg)
    )

    return False


# ============================================================
# SAVE CONFIG
# ============================================================

def save_config(
    base_url,
    session_id
):

    try:

        res = requests.post(
            base_url
            + "/nitro/v1/config/"
            "nsconfig?action=save",
            json={
                "nsconfig": {}
            },
            headers={
                "Cookie":
                "NITRO_AUTH_TOKEN="
                + str(session_id),

                "Content-Type":
                "application/json"
            },
            verify=False,
            timeout=10
        )

        if res.status_code in [
            200,
            201
        ]:

            log(
                "[+] DRCir Primary uzerinde "
                "'save nsconfig' yapildi."
            )

            return True

        log(
            "[!] Config kaydedilemedi: "
            + str(get_response_message(res))
        )

    except Exception as e:

        log(
            "[!] Config kaydedilirken hata: "
            + str(e)
        )

    return False


# ============================================================
# MAIN SYNC
# ============================================================

def run_sync():

    log(
        "=================================================="
    )

    log(
        "[*] NETSCALER SMART-SYNC BASLATILIYOR"
    )

    log(
        "=================================================="
    )

    # --------------------------------------------------------
    # FIND MAINANBUL PRIMARY
    # --------------------------------------------------------

    MAIN_url, MAIN_session = (
        find_active_primary_node(
            MAIN_NODES,
            MAIN_PASS,
            "MAINANBUL"
        )
    )

    # --------------------------------------------------------
    # FIND DRCIR PRIMARY
    # --------------------------------------------------------

    DRC_url, DRC_session = (
        find_active_primary_node(
            DRC_NODES,
            DRC_PASS,
            "DRCIR"
        )
    )

    if (
        not MAIN_url
        or
        not DRC_url
    ):

        log(
            "[CRITICAL] HA Primary "
            "dugumler bulunamadi."
        )

        return

    log(
        "[+] MAINanbul Primary: "
        + MAIN_url
    )

    log(
        "[+] DRCir Primary   : "
        + DRC_url
    )

    log("")

    total_ops = 0

    # ========================================================
    # READ MAINANBUL DATA
    # ========================================================

    MAIN_data = {}

    log(
        "[*] MAINanbul kaynaklari okunuyor..."
    )

    for r_type in PRIMARY_RESOURCES:

        MAIN_lMAIN = get_resources(
            MAIN_url,
            MAIN_session,
            r_type
        )

        MAIN_data[r_type] = {}

        for item in MAIN_lMAIN:

            key = get_resource_key(
                r_type,
                item
            )

            if key:

                MAIN_data[r_type][
                    key
                ] = item

        log(
            "    [OK] "
            + r_type
            + ": "
            + str(
                len(
                    MAIN_data[r_type]
                )
            )
            + " kaynak"
        )

    # ========================================================
    # READ DRCIR DATA
    # ========================================================

    DRC_data = {}

    log(
        "[*] DRCir kaynaklari okunuyor..."
    )

    for r_type in PRIMARY_RESOURCES:

        DRC_lMAIN = get_resources(
            DRC_url,
            DRC_session,
            r_type
        )

        DRC_data[r_type] = {}

        for item in DRC_lMAIN:

            key = get_resource_key(
                r_type,
                item
            )

            if key:

                DRC_data[r_type][
                    key
                ] = item

        log(
            "    [OK] "
            + r_type
            + ": "
            + str(
                len(
                    DRC_data[r_type]
                )
            )
            + " kaynak"
        )

    # ========================================================
    # DELETION ORDER
    # ========================================================

    DELETION_ORDER = [

        "lbvserver_service_binding",

        "lbvserver_responderpolicy_binding",
        "lbvserver_rewritepolicy_binding",

        "csvserver_cspolicy_binding",
        "csvserver_responderpolicy_binding",
        "csvserver_rewritepolicy_binding",

        "policydataset_value_binding",

        "lbvserver",

        "csvserver",

        "service",
        "servicegroup",
        "server",

        "cspolicy",
        "csaction",

        "responderpolicy",
        "responderaction",

        "rewritepolicy",
        "rewriteaction",

        "policydataset"
    ]

    # ========================================================
    # DELETE ORPHANS
    # ========================================================

    log(
        "[*] Yetim kaynaklar kontrol ediliyor..."
    )

    for r_type in DELETION_ORDER:

        if r_type not in DRC_data:
            continue

        for key in lMAIN(
            DRC_data[r_type].keys()
        ):

            if key in MAIN_data[r_type]:
                continue

            log(
                "    [!] Yetim tespit edildi ["
                + r_type
                + "]: "
                + str(key)
            )

            delete_key = key

            if r_type in [
                "policydataset_value_binding",
                "lbvserver_service_binding",
                "csvserver_cspolicy_binding"
            ]:

                delete_key = (
                    DRC_data[r_type][key]
                )

            elif r_type in POLICY_BINDING_RESOURCES:

                delete_key = (
                    DRC_data[r_type][key]
                )

            deleted = delete_orphan_resource(
                DRC_url,
                DRC_session,
                r_type,
                delete_key
            )

            if deleted:

                total_ops += 1

                if key in DRC_data[r_type]:

                    del DRC_data[
                        r_type
                    ][key]

    # ========================================================
    # CREATE MISSING RESOURCES
    # ========================================================

    log(
        "[*] Eksik kaynaklar kontrol ediliyor..."
    )

    for r_type in PRIMARY_RESOURCES:

        for key, item in (
            MAIN_data[r_type].items()
        ):

            if key in DRC_data[r_type]:
                continue

            log(
                "    [+] ["
                + r_type
                + "] Yeni ekleniyor: "
                + str(key)
            )

            ok, msg = create_resource(
                DRC_url,
                DRC_session,
                r_type,
                item
            )

            if ok:

                log(
                    "        [OK] Eklendi."
                )

                total_ops += 1

                DRC_data[
                    r_type
                ][key] = item

            else:

                log(
                    "        [!] Hata: "
                    + str(msg)
                )

    # ========================================================
    # UPDATE CHANGED RESOURCES
    # ========================================================

    log(
        "[*] Degisen kaynaklar kontrol ediliyor..."
    )

    for r_type in PRIMARY_RESOURCES:

        if r_type == (
            "policydataset_value_binding"
        ):

            continue

        for key, source_item in (
            MAIN_data[r_type].items()
        ):

            if key not in DRC_data[r_type]:
                continue

            source_payload = prepare_payload(
                r_type,
                source_item
            )

            target_payload = prepare_payload(
                r_type,
                DRC_data[r_type][key]
            )

            if (
                source_payload
                ==
                target_payload
            ):

                continue

            log(
                "    [~] Degisiklik tespit edildi ["
                + r_type
                + "]: "
                + str(key)
            )

            ok, msg = update_resource(
                DRC_url,
                DRC_session,
                r_type,
                key,
                source_item
            )

            if ok:

                log(
                    "        [OK] Guncellendi."
                )

                total_ops += 1

                DRC_data[
                    r_type
                ][key] = source_item

            else:

                log(
                    "        [!] Update hatasi: "
                    + str(msg)
                )

    # ========================================================
    # DATASET VALUE BINDINGS UPDATE
    # ========================================================

    source_bindings = MAIN_data.get(
        "policydataset_value_binding",
        {}
    )

    target_bindings = DRC_data.get(
        "policydataset_value_binding",
        {}
    )

    for key in lMAIN(
        target_bindings.keys()
    ):

        if key not in source_bindings:
            continue

        source_item = (
            source_bindings[key]
        )

        target_item = (
            target_bindings[key]
        )

        source_payload = prepare_payload(
            "policydataset_value_binding",
            source_item
        )

        target_payload = prepare_payload(
            "policydataset_value_binding",
            target_item
        )

        if (
            source_payload
            ==
            target_payload
        ):

            continue

        log(
            "    [~] Dataset value "
            "degisikligi: "
            + str(key)
        )

        ok, msg = delete_dataset_value_binding(
            DRC_url,
            DRC_session,
            target_item
        )

        if not ok:

            log(
                "        [!] Eski binding silinemedi: "
                + str(msg)
            )

            continue

        ok, msg = create_resource(
            DRC_url,
            DRC_session,
            "policydataset_value_binding",
            source_item
        )

        if ok:

            log(
                "        [OK] Dataset value guncellendi."
            )

            total_ops += 1

            target_bindings[
                key
            ] = source_item

        else:

            log(
                "        [!] Yeni binding "
                "eklenemedi: "
                + str(msg)
            )

    # ========================================================
    # SAVE
    # ========================================================

    if total_ops > 0:

        log(
            "[*] Degisiklikler kaydediliyor..."
        )

        save_config(
            DRC_url,
            DRC_session
        )

    else:

        log(
            "[*] Degisiklik bulunmadi. "
            "Save yapilmayacak."
        )

    log("")

    log(
        "[*] SENKRONIZASYON TAMAMLANDI. "
        "Toplam Islem: "
        + str(total_ops)
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    run_sync()