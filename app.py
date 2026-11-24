from flask import Flask, request, render_template_string, redirect, make_response, session, abort
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

def db_query(query, params=()):
    """Ejecuta consultas parametrizadas de forma segura contra SQL Injection"""
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return result

# --- MITIGACIÓN CABECERAS HTTP (Alertas OWASP ZAP) ---
@app.after_request
def agregar_cabeceras_seguridad(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    response.headers['Cross-Origin-Embedder-Policy'] = "require-corp"
    response.headers['Cross-Origin-Opener-Policy'] = "same-origin"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# --- LOGIN SEGURO (Mitigación SQLi y Cookie Flags) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '')
        pw = request.form.get('password', '')

        # Consulta parametrizada: neutraliza inyección SQL
        usuarios = db_query(
            "SELECT * FROM usuarios WHERE username = ? AND password = ?",
            (user, pw)
        )

        if usuarios:
            usuario = usuarios[0]
            session['csrf_token'] = secrets.token_hex(16)
            resp = make_response(redirect('/dashboard'))
            resp.set_cookie(
                'user_session',
                usuario['username'],
                httponly=True,
                samesite='Lax'
            )
            return resp
        return "<h3>Acceso denegado</h3><a href='/login'>Volver</a>", 401

    return '''
        <h2>Login del Sistema Académico</h2>
        <form method="post">
            Usuario: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Ingresar">
        </form>
    '''

# --- DASHBOARD SEGURO (Mitigación XSS con Jinja2 y Token CSRF) ---
@app.route('/dashboard')
def dashboard():
    username = request.cookies.get('user_session')
    if not username:
        return redirect('/login')

    registros = db_query("SELECT * FROM usuarios WHERE username = ?", (username,))
    if not registros:
        return redirect('/login')
    datos = registros[0]

    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

    # Jinja2 escapa automáticamente {{ ... }} previniendo XSS almacenado
    template = """
    <h1>Panel de {{ datos['username'] }}</h1>
    <p><b>Rol:</b> {{ datos['rol'] }}</p>
    <p><b>Biografía:</b> {{ datos['bio'] }}</p>
    <hr>
    <h3>Actualizar Biografía (Protegido con CSRF Token)</h3>
    <form action="/update_bio" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="nueva_bio" placeholder="Escribe algo...">
        <input type="submit" value="Guardar Cambios">
    </form>
    <br><a href="/logout">Cerrar Sesión</a>
    """
    return render_template_string(template, datos=datos, csrf_token=session['csrf_token'])

@app.route('/update_bio', methods=['POST'])
def update_bio():
    username = request.cookies.get('user_session')
    token_form = request.form.get('csrf_token')
    token_sesion = session.get('csrf_token')

    # Validación estricta del token CSRF
    if not token_sesion or token_form != token_sesion:
        abort(403, description="Token CSRF inválido o ausente")

    if username:
        nueva_bio = request.form.get('nueva_bio', '')
        db_query("UPDATE usuarios SET bio = ? WHERE username = ?", (nueva_bio, username))
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/login'))
    resp.set_cookie('user_session', '', expires=0)
    return resp

@app.route('/')
def home():
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=False, port=5000)
