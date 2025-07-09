import re
from oletools.olevba import VBA_Parser, VBA_Scanner
_OBFUSCATION_RE = r"[A-Za-z0-9+/]{100,}={0,2}"

def analyze(path: str) -> dict:
    vb = VBA_Parser(path)
    out = {
        "autoexec_funcs": set(),
        "suspicious_calls": set(),
        "string_obfuscation": 0,
        "has_drops_payload": False,
        "macro_modules": [],
    }

    try:
        for (_, stream_path, mod_name, code) in vb.extract_macros():
            out["macro_modules"].append({"name": mod_name, "size": len(code)})

            # 1) Auto-exec detection
            analysis = vb.analyze_macros()  # list of (type, keyword, description)
            for kw_type, kw, _ in analysis:
                if kw_type == "AutoExec":
                    out["autoexec_funcs"].add(kw)
                elif kw_type == "Suspicious":
                    out["suspicious_calls"].add(kw)

            # 2) Suspicious API calls (oletools builtin)
            scan = VBA_Scanner(code)
            out["suspicious_calls"].update([kw for kw, _, _ in scan.scan()])

            # 3) Obfuscation
            if re.search(_OBFUSCATION_RE, code):
                out["string_obfuscation"] += 1

            # 4) Payload dropper heuristics
            if any(i in code.lower() for i in ("urldownloadtofile", "adodb.stream")):
                out["has_drops_payload"] = True

    finally:
        vb.close()

    # Cast sets → sorted lists for JSON serialisation
    for k in ("autoexec_funcs", "suspicious_calls"):
        out[k] = sorted(out[k])

    return out
