from flask import request, redirect

def route():
    return redirect(request.args.get("next"))
