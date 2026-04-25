def hex_to_rgba(hex_color, alpha=0.15):
    """Convert #rrggbb to rgba(r,g,b,alpha) — Plotly-safe."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"

# Pre-defined palette
COLORS = {
    "HIGH":   "#ff4560",
    "MEDIUM": "#ffa500",
    "LOW":    "#00f5a0",
    "accent": "#00f5a0",
    "accent2":"#00c8ff",
    "purple": "#a855f7",
}

def fill(hex_color, alpha=0.15):
    return hex_to_rgba(hex_color, alpha)
