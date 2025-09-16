from __future__ import annotations
from typing import List

def name_to_phrase(name: str) -> str:
    if name.startswith("mem:"): return f"recent {name[4:]}"
    if name.startswith("mode="): return f"system was '{name.split('=',1)[1]}'"
    if name.startswith("evt:"):
        k,v = name[4:].split("=",1) if "=" in name else (name[4:],"")
        if k in {"location","zone","room"}: return f"{v} activity"
        if k in {"type","event","sensor_type"}: return f"{v} event"
        return f"{k}={v}"
    if name.startswith("tag:"): return f"device tag '{name[4:]}'"
    if name.startswith("num:"): return name.replace("num:","").replace(":"," ")
    return name

def format_explanation(level:str, phrases:List[str], prob:float, low_conf:bool) -> str:
    core = ", ".join(phrases[:3]) if phrases else "patterns in the input"
    c = f"{prob:.2f}"
    return f"{level.capitalize()} {'with low confidence ' if low_conf else ''}based on {core}. Confidence={c}."
