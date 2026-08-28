"""Unbound pythonmod logger for E5.

This module sees DNS messages after kernel reassembly. It cannot observe
IPv4 MF/offset. Rℓ2/B5 stays in detector.py (packet sidecar).
"""

import json
import time

LOG = "/app/unbound_queries.jsonl"


def _append(row):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def init(id, cfg):
    log_info("e5mod: init id=%d port=%d script=%s" % (id, cfg.port, mod_env["script"]))
    return True


def init_standard(id, env):
    log_info("e5mod: init_standard id=%d port=%d" % (id, env.cfg.port))
    return True


def deinit(id):
    log_info("e5mod: deinit id=%d" % id)
    return True


def inform_super(id, qstate, superqstate, qdata):
    return True


def operate(id, event, qstate, qdata):
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True
    if event == MODULE_EVENT_MODDONE:
        qname = qstate.qinfo.qname_str if qstate.qinfo else ""
        rcode = -1
        if qstate.return_msg and qstate.return_msg.rep:
            rcode = int(qstate.return_msg.rep.flags) & 0xF
        _append({"ts": time.time(), "qname": qname, "rcode": rcode})
        qstate.ext_state[id] = MODULE_FINISHED
        return True
    log_err("e5mod: unexpected event")
    qstate.ext_state[id] = MODULE_ERROR
    return True


log_info("e5mod: script loaded")
