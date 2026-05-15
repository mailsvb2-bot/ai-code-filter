from fastapi.responses import HTMLResponse

def route(request):
    return HTMLResponse(f"<h1>{request.query_params['name']}</h1>")
