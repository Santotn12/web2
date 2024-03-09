from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import NullPool
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

# ...

@classmethod
def crear_usuario(cls, nombre, contrasena):
    hash_contrasena = generate_password_hash(contrasena, method='pbkdf2:sha256')
    nuevo_usuario = cls(nombre=nombre, contrasena=hash_contrasena)
    db.session.add(nuevo_usuario)
    db.session.commit()
    return nuevo_usuario

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'pbkdf2:sha256'  # Cambia esto por una clave segura
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuario.db'
app.config['SQLALCHEMY_POOL_CLASS'] = NullPool
db = SQLAlchemy(app)
#--------------------------------------------------------------------------------------------#
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), unique=True, nullable=False)
    contrasena = db.Column(db.String(120), nullable=False)
    tareas = db.relationship('Tarea', backref='usuario', lazy=True)
    
    @classmethod
    def crear_usuario(cls, nombre, contrasena):
        hash_contrasena = generate_password_hash(contrasena, method='pbkdf2:sha256')
        nuevo_usuario = cls(nombre=nombre, contrasena=hash_contrasena)
        db.session.add(nuevo_usuario)
        db.session.commit()
        return nuevo_usuario
class Tarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.String(200), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
#--------------------------------------------------------------------------------------------#
@app.before_request
def verificar_sesion():
    ruta_protegida = ['/home']  # Actualiza la ruta protegida según tus necesidades

    if request.endpoint in ruta_protegida and 'usuario_id' not in session:
        return redirect(url_for('login'))

@app.route('/')
def inicio():
    return render_template('inicio.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        nombre = request.form['nombre']
        contrasena = request.form['contrasena']

        usuario = Usuario.query.filter_by(nombre=nombre).first()

        if usuario and check_password_hash(usuario.contrasena, contrasena):
            session['usuario_id'] = usuario.id
            return redirect(url_for('home'))
        else:
           if usuario and (nombre == "" or nombre == usuario.nombre):
                error = 'Usuario y/o contrasena incorrecto'

   

@app.route('/logout')
def logout():
    session.pop('usuario_id', None)
    return redirect(url_for('inicio'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        contrasena = request.form['contrasena']

        if Usuario.query.filter_by(nombre=nombre).first():
            return render_template('registro.html', error='El nombre de usuario ya está en uso.')

        Usuario.crear_usuario(nombre, contrasena)
        return redirect(url_for('login'))

    return render_template('registro.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/cargar_tareas', methods=['POST'])
def cargar_tareas():
    usuario_id = session.get('usuario_id')
    
    if usuario_id:
        usuario = db.session.query(Usuario).get(usuario_id)
        tareas_desde_frontend = request.json.get('tareas', [])

        for tarea_en_frontend in tareas_desde_frontend:
            texto = tarea_en_frontend.get('texto')
            nueva_tarea = Tarea(texto=texto, usuario=usuario)
            db.session.add(nueva_tarea)

        db.session.commit()

        return jsonify({"mensaje": "Tareas cargadas correctamente."})
    
    return jsonify({"error": "Usuario no autenticado."}), 401
@app.route('/obtener_tareas', methods=['GET'])
def obtener_tareas():
    usuario_id = session.get('usuario_id')

    if usuario_id:
        usuario = db.session.get(Usuario, usuario_id)

        tareas_usuario = Tarea.query.filter_by(usuario=usuario).all()

        tareas = [{"id": tarea.id, "texto": tarea.texto} for tarea in tareas_usuario]

        return jsonify({"tareas": tareas})

    return jsonify({"error": "Usuario no autenticado."}), 401

@app.route('/eliminar_tarea', methods=['POST'])
def eliminar_tarea():
    tarea_id = request.json.get('tarea_id')

    tarea = db.session.get(Tarea, tarea_id)

    if tarea:
        db.session.delete(tarea)
        db.session.commit()
        return jsonify({"mensaje": "Tarea eliminada correctamente."})
    else:
        return jsonify({"error": "Tarea no encontrada."}), 404

#--------------------------------------------------------------------------------------------#
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
