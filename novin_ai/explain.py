from typing import List, Optional

def name_to_phrase(name: str) -> str:
    """Convert a feature name to a human-readable phrase."""
    if not name:
        return ""
    
    # Handle common patterns
    if name.startswith("mem:"):
        return f"{name[4:].replace('_', ' ').capitalize()}"
    
    return name.replace("_", " ").capitalize()

def format_explanation(level: str, phrases: List[str], confidence: float, 
                      is_low_confidence: bool = False) -> str:
    """Format the final explanation for the user."""
    if not phrases:
        return f"No specific threats detected. Security level: {level}."
    
    # Join phrases with appropriate grammar
    if len(phrases) == 1:
        reason = phrases[0]
    else:
        reason = ", ".join(phrases[:-1]) + f", and {phrases[-1]}"
    
    confidence_note = " (low confidence)" if is_low_confidence else ""
    
    return (
        f"Security level: {level.capitalize()}{confidence_note}. "
        f"Based on: {reason}."
    )
