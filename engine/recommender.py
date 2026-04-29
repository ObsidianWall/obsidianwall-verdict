#

def generate_suggestions(context):
    suggestions = []

    if context["estimated_cost"] > 50:
        suggestions.append("Use smaller VM instance")
        suggestions.append("Switch to serverless architecture")

    return suggestions