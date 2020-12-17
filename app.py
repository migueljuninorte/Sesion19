import functools
import os

from OpenSSL.crypto import FILETYPE_PEM #certificado
from flask import Flask, render_template, flash, request, redirect, url_for, jsonify, session, send_file, current_app, g, make_response #para pdf
import pdfkit #para pdf
path_wkhtmltopdf = 'venv\\include\\wkhtmltopdf\\bin\\wkhtmltopdf.exe'
config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
resultado = {}

from werkzeug.security import generate_password_hash, check_password_hash #Libería PBK

import utils
from db import get_db, close_db
from formularios import Contactenos
from message import mensajes
from sqlite3 import Error

app = Flask( __name__ )
app.secret_key = os.urandom( 24 )


@app.route( '/' )
def index():
    if g.user:
        return redirect( url_for( 'send' ) )
    return render_template( 'login.html' )


@app.route( '/register', methods=('GET', 'POST') )
def register():
    if g.user:
        return redirect( url_for( 'send' ) )
    try:
        if request.method == 'POST':
            username = request.form['usuario']
            password = request.form['password']
            email = request.form['email']
            error = None
            db = get_db()

            if not utils.isUsernameValid( username ):
                error = "El usuario debe ser alfanumerico o incluir solo '.','_','-'"
                flash( error )
                return render_template( 'register.html' )

            if not utils.isPasswordValid( password ):
                error = 'La contraseña debe contenir al menos una minúscula, una mayúscula, un número y 8 caracteres'
                flash( error )
                return render_template( 'register.html' )

            if not utils.isEmailValid( email ):
                error = 'Correo invalido'
                flash( error )
                return render_template( 'register.html' )

            if db.execute( 'SELECT id FROM usuarios WHERE correo = ?', (email,) ).fetchone() is not None:
                error = 'El correo ya existe'.format( email )
                flash( error )
                return render_template( 'register.html' )
            
            hashPassword = generate_password_hash(password) #Generar hash+salt+PBK

            db.execute(
                'INSERT INTO usuarios (usuario, correo, contraseña) VALUES (?,?,?)',
                (username, email, hashPassword)
            )
            db.commit()

            # yag = yagmail.SMTP('micuenta@gmail.com', 'clave') #modificar con tu informacion personal
            # yag.send(to=email, subject='Activa tu cuenta',
            #        contents='Bienvenido, usa este link para activar tu cuenta ')
            flash( 'Revisa tu correo para activar tu cuenta' )
            return render_template( 'login.html' )
        return render_template( 'register.html' )
    except:
        return render_template( 'register.html' )


@app.route( '/login', methods=('GET', 'POST') )
def login():
    try:
        if request.cookies.get('uid'):
            g.user = request.cookies.get('uid')
            session['user_id'] = request.cookies.get('uid')

        if g.user:
            return redirect( url_for( 'send' ) )
        if request.method == 'POST':
            db = get_db()
            error = None
            username = request.form['usuario']
            password = request.form['password']

            if not username:
                error = 'Debes ingresar el usuario'
                flash( error )
                return render_template( 'login.html' )

            if not password:
                error = 'Contraseña requerida'
                flash( error )
                return render_template( 'login.html' )

            user = db.execute(
                'SELECT * FROM usuarios WHERE usuario = ?', (username, )
            ).fetchone()

            if user is None:
                error = 'Usuario o contraseña inválidos'
            else:
                if check_password_hash(user['contraseña'],password):
                    session.clear() #limpiar la sesión
                    userid = user[0]
                    session['user_id'] = userid #creación de sesión
                    #creación de cookies
                    resp = make_response(redirect( url_for( 'send' ) ))
                    resp.set_cookie('username',username,max_age=60*60*24)
                    resp.set_cookie('uid',str(userid),max_age=60*60*24)

                    return resp
            flash( error )
        return render_template( 'login.html' )
    except:
        return render_template( 'login.html' )


@app.route( '/contactUs', methods=('GET', 'POST') )
def contactUs():
    form = Contactenos()
    return render_template( 'contactus.html', titulo='Contactenos', form=form )


def login_required(view):
    @functools.wraps( view )
    def wrapped_view():
        if g.user is None:
            return redirect( url_for( 'login' ) )
        return view( )
    return wrapped_view 

@app.route( '/downloadpdf', methods=('GET', 'POST') )
@login_required
def downloadpdf():
    return send_file( "resources/doc.pdf", as_attachment=True )


@app.route( '/downloadimage', methods=('GET', 'POST') )
@login_required
def downloadimage():
    return send_file( "resources/image.png", as_attachment=True )


@app.route( '/send', methods=('GET', 'POST') )
@login_required
def send():
    db = get_db()
    if request.method == 'POST':
        #from_id = g.user['id'] 
        from_id=request.cookies.get('uid')
        to_username = request.form['para']
        subject = request.form['asunto']
        body = request.form['mensaje']
    
        

        if not to_username:
            flash( 'Para campo requerido' )
            return render_template( 'send.html' )

        if not subject:
            flash( 'Asunto es requerido' )
            return render_template( 'send.html' )

        if not body:
            flash( 'Mensaje es requerido' )
            return render_template( 'send.html' )

        error = None
        userto = None

        userto = db.execute(
            'SELECT * FROM usuarios WHERE usuario = ?', (to_username,)
        ).fetchone()

        if userto is None:
            error = 'No existe ese usuario'

        if error is not None:
            flash( error )

        else:
            db = get_db()
            db.execute(
                'INSERT INTO mensajes (from_id, to_id, asunto, mensaje)'
                ' VALUES (?, ?, ?, ?)',
                (from_id, userto['id'], subject, body)
            )
            db.commit()
            flash( "Mensaje Enviado" )
    userto = db.execute("Select usuario FROM usuarios").fetchall()
    return render_template( 'send.html',users=userto )

@app.route('/mensajes')
@login_required
def mensajes():
    try:
        db = get_db()
        global resultado
        resultado = db.execute("SELECT message_id AS 'Codigo Mensaje', from_id AS 'Código Remitente', u1.usuario AS 'Usuario Remitente', " +
                                    " to_id AS 'Código destinatario', u2.usuario AS 'Usuario Destinatario', asunto AS 'Asunto', " +
                                    " mensaje AS 'Mensaje' " +
                                " FROM usuarios u1, usuarios u2, mensajes " +
                                " WHERE from_id = u1.id AND to_id = u2.id;").fetchall()
        close_db()
        return render_template('mensajes.html',titulo="Mensajes", data = resultado)
    except Error as e:    
        return render_template('error.html', error=e)

@app.route('/descargar')
@login_required
def descargar_mensajes():
    rendered = render_template('mensajes.html',titulo="Mensajes", data = resultado)
    #print ("Resultado", resultado)
    pdf = pdfkit.from_string(rendered, False, configuration=config)
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['content-Disposition'] = 'inline; filename=archivo.pdf'
    #response.headers['Content-Disposition'] = 'attachment; filename=archivo.pdf'

    return response
    #return render_template('base.html')

@app.before_request
def load_logged_in_user():
    user_id = session.get( 'user_id' )

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM usuarios WHERE id = ?', (user_id,)
        ).fetchone()


@app.route( '/logout' )
def logout():
    session.clear()
    resp = make_response(redirect( url_for( 'login' ) ))
    resp.delete_cookie('username','/',domain=None)
    resp.delete_cookie('uid','/',domain=None)
    return resp


if __name__ == '__main__':
    #app.run(port=80,debug=True)
    app.run(host='localhost', port=443, ssl_context=('micertificado.cer', 'llaveprivada.pem')) #Certificado