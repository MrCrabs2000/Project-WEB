import flask
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from data import db_session
from data.users import User, Admin
import sqlalchemy.exc
import json
from io import BytesIO
from PIL import Image
import base64


app = flask.Flask(__name__)
app.secret_key = '25112008'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
ADMIN_CODE = '1234'


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    user = session.query(User).get(user_id) or session.query(Admin).get(user_id)
    session.close()
    return user


db_session.global_init("db/users.db")


def process_image(image_file):
    if not image_file:
        return None
    try:
        img = Image.open(image_file.stream)
        img.thumbnail((200, 200))
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format='PNG')
        return img_byte_arr.getvalue()
    except Exception:
        print('Ошибка загрузки фото профиля')
        return None


@app.route('/')
@app.route('/reminds')
def index():
    if current_user.is_authenticated:
        session = db_session.create_session()
        if current_user.role == 'admin':
            user_class = Admin
        else:
            user_class = User
        user = session.query(user_class).get(current_user.id)
        remindss = {}
        if user.reminds_names:
            remindss['names'] = json.loads(user.reminds_names)
        else:
            remindss['names'] = {}
        if user.reminds_opises:
            remindss['opises'] = json.loads(user.reminds_opises)
        else:
            remindss['opises'] = {}
        if user.reminds_deadlines:
            remindss['deadlines'] = json.loads(user.reminds_deadlines)
        else:
            remindss['deadlines'] = {}
        if user.reminds_statuses:
            remindss['statuses'] = json.loads(user.reminds_statuses)
        else:
            remindss['statuses'] = {}
        all_users = []
        if current_user.role == 'admin':
            users = session.query(User).all()
            all_users = []
            for us in users:
                userr = {}
                userr['id'] = us.id
                userr['name'] = us.username
                if us.reminds_names:
                    userr['reminds_count'] = len(json.loads(us.reminds_names))
                else:
                    userr['reminds_count'] = 0
                if us.reminds_statuses:
                    res = 0
                    for s in json.loads(us.reminds_statuses).values():
                        if s == 'complited':
                            res += 1
                    userr['complited_reminds'] = res
                else:
                    userr['complited_reminds'] = 0
                if us.photoprofile:
                    userr['photo'] = base64.b64encode(us.photoprofile).decode('utf-8')
                else:
                    userr['photo'] = None
                all_users.append(userr.copy())
            admin_users()

        session.close()

        if user.photoprofile:
            photo = base64.b64encode(user.photoprofile).decode('utf-8')
        else:
            photo = None

        return flask.render_template('base.html',
                               logged_in=True,
                               username=current_user.username,
                               reminds=remindss,
                               role=current_user.role,
                               photo_base64=photo,
                               all_users=all_users)
    return flask.render_template('base.html', logged_in=False)


@app.route('/register', methods=['POST'])
def register():
    username = flask.request.form['username']
    password = flask.request.form['password']
    password_confirm = flask.request.form['password_confirm']
    admin_code = flask.request.form.get('admin_code', '')
    photo = flask.request.files.get('photo')

    if password != password_confirm:
        flask.flash('Пароли не совпадают', 'error')
        return flask.redirect(flask.url_for('index'))

    session = db_session.create_session()

    if session.query(User).filter(User.username == username).first() or \
            session.query(Admin).filter(Admin.username == username).first():
        flask.flash('Пользователь с таким именем уже существует', 'error')
        session.close()
        return flask.redirect(flask.url_for('index'))

    try:
        photo_data = process_image(photo)

        if admin_code == ADMIN_CODE:
            new_user = Admin(
                username=username,
                password=generate_password_hash(password),
                reminds_names=json.dumps({}),
                reminds_opises=json.dumps({}),
                reminds_deadlines=json.dumps({}),
                reminds_statuses=json.dumps({}),
                photoprofile=photo_data,
                role='admin'
            )
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                reminds_names=json.dumps({}),
                reminds_opises=json.dumps({}),
                reminds_deadlines=json.dumps({}),
                reminds_statuses=json.dumps({}),
                photoprofile=photo_data,
                role='user'
            )

        session.add(new_user)
        session.commit()
        login_user(new_user)
    except Exception:
        session.rollback()
    session.close()

    return flask.redirect(flask.url_for('index'))


@app.route('/login', methods=['POST'])
def login():
    username = flask.request.form['username']
    password = flask.request.form['password']

    session = db_session.create_session()
    user = session.query(User).filter(User.username == username).first() or \
           session.query(Admin).filter(Admin.username == username).first()
    session.close()

    if user and check_password_hash(user.password, password):
        login_user(user)
    else:
        flask.flash('Неверное имя пользователя или пароль', 'error')

    return flask.redirect(flask.url_for('index'))


@app.route('/logout')
@login_required
def logout():
    session = db_session.create_session()
    if current_user.role == 'admin':
        user_class = Admin
    else:
        user_class = User
    user = session.query(user_class).get(current_user.id)

    for field in ['reminds_names', 'reminds_opises', 'reminds_deadlines', 'reminds_statuses']:
        data = getattr(user, field)
        if data and isinstance(json.loads(data), list):
            converted = {}
            for i, v in enumerate(json.loads(data)):
                converted[str(i)] = v
            setattr(user, field, json.dumps(converted))

    session.commit()
    session.close()
    logout_user()
    return flask.redirect(flask.url_for('index'))


@app.route('/add_reminder', methods=['POST'])
@login_required
def add_reminder():
    title = flask.request.form['title']
    description = flask.request.form.get('description', '')
    deadline = flask.request.form['deadline']

    session = db_session.create_session()
    if current_user.role == 'admin':
        user_class = Admin
    else:
        user_class = User
    user = session.query(user_class).get(current_user.id)

    if user.reminds_names:
        names = json.loads(user.reminds_names)
    else:
        names = {}
    if user.reminds_opises:
        opises = json.loads(user.reminds_opises)
    else:
        opises = {}
    if user.reminds_deadlines:
        deadlines = json.loads(user.reminds_deadlines)
    else:
        deadlines = {}
    if user.reminds_statuses:
        statuses = json.loads(user.reminds_statuses)
    else:
        statuses = {}
    if names:
        new_id = str(max([int(k) for k in names.keys()] + [0]) + 1)
    else:
        new_id = '1'

    names[new_id] = title
    opises[new_id] = description
    deadlines[new_id] = deadline
    statuses[new_id] = 'in_progress'

    user.reminds_names = json.dumps(names)
    user.reminds_opises = json.dumps(opises)
    user.reminds_deadlines = json.dumps(deadlines)
    user.reminds_statuses = json.dumps(statuses)

    session.commit()
    session.close()
    return flask.redirect(flask.url_for('index'))


@app.route('/complete_reminder/<reminder_id>')
@login_required
def complete_reminder(reminder_id):
    session = db_session.create_session()
    if current_user.role == 'admin':
        user_class = Admin
    else:
        user_class = User
    user = session.query(user_class).get(current_user.id)

    if user.reminds_statuses:
        statuses = json.loads(user.reminds_statuses)
    else:
        statuses = {}

    if reminder_id in statuses:
        statuses[reminder_id] = 'completed'
        user.reminds_statuses = json.dumps(statuses)
        session.commit()

    session.close()
    return flask.redirect(flask.url_for('index'))


@app.route('/delete_reminder/<reminder_id>')
@login_required
def delete_reminder(reminder_id):
    session = db_session.create_session()
    if current_user.role == 'admin':
        user_class = Admin
    else:
        user_class = User
    user = session.query(user_class).get(current_user.id)

    if user.reminds_names:
        names = json.loads(user.reminds_names)
    else:
        names = {}
    if user.reminds_opises:
        opises = json.loads(user.reminds_opises)
    else:
        opises = {}
    if user.reminds_deadlines:
        deadlines = json.loads(user.reminds_deadlines)
    else:
        deadlines = {}
    if user.reminds_statuses:
        statuses = json.loads(user.reminds_statuses)
    else:
        statuses = {}

    if reminder_id in names:
        names.pop(reminder_id)
        opises.pop(reminder_id, None)
        deadlines.pop(reminder_id, None)
        statuses.pop(reminder_id, None)

        user.reminds_names = json.dumps(names)
        user.reminds_opises = json.dumps(opises)
        user.reminds_deadlines = json.dumps(deadlines)
        user.reminds_statuses = json.dumps(statuses)

        session.commit()
    session.close()
    return flask.redirect(flask.url_for('index'))


@app.route('/edit_reminder', methods=['POST'])
@login_required
def edit_reminder():
    reminder_id = flask.request.form['reminder_id']
    title = flask.request.form['title']
    description = flask.request.form.get('description', '')
    deadline = flask.request.form['deadline']

    session = db_session.create_session()
    if current_user.role == 'admin':
        user_class = Admin
    else:
        user_class = User
    user = session.query(user_class).get(current_user.id)

    if user.reminds_names:
        names = json.loads(user.reminds_names)
    else:
        names = {}
    if user.reminds_opises:
        opises = json.loads(user.reminds_opises)
    else:
        opises = {}
    if user.reminds_deadlines:
        deadlines = json.loads(user.reminds_deadlines)
    else:
        deadlines = {}
    if user.reminds_statuses:
        statuses = json.loads(user.reminds_statuses)
    else:
        statuses = {}

    if reminder_id in names:
        names[reminder_id] = title
        opises[reminder_id] = description
        deadlines[reminder_id] = deadline
        statuses[reminder_id] = 'in_progress'

        user.reminds_names = json.dumps(names)
        user.reminds_opises = json.dumps(opises)
        user.reminds_deadlines = json.dumps(deadlines)
        user.reminds_statuses = json.dumps(statuses)

        session.commit()

    session.close()
    return flask.redirect(flask.url_for('index'))


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return flask.redirect(flask.url_for('index'))

    session = db_session.create_session()
    try:
        users = session.query(User).all()
        users_data = []

        for user in users:
            if user.reminds_names:
                reminds_count = len(json.loads(user.reminds_names))
            else:
                reminds_count = 0
            if user.reminds_statuses:
                res = 0
                for s in json.loads(user.reminds_statuses).values():
                    if s != 'in_progress':
                        res += 1
                completed = res
            else:
                completed = 0
            if user.photoprofile:
                photo = base64.b64encode(user.photoprofile).decode('utf-8')
            else:
                photo = None

            users_data.append({
                'id': user.id,
                'username': user.username,
                'reminds_count': reminds_count,
                'completed_reminds': completed,
                'photo': photo
            })
        session.close()
        return flask.render_template('admin_users.html',
                               users=users_data,
                               current_user=current_user)

    except Exception:
        session.close()
        return flask.redirect(flask.url_for('index'))


@app.route('/admin/view_user/<int:user_id>')
@login_required
def view_user(user_id):
    if current_user.role != 'admin':
        return flask.redirect(flask.url_for('index'))

    session = db_session.create_session()
    user = session.query(User).get(user_id)

    if not user:
        session.close()
        return flask.redirect(flask.url_for('index'))

    reminds = {}
    if user.reminds_names:
        reminds['names'] = json.loads(user.reminds_names)
    else:
        reminds['names'] = {}
    if user.reminds_opises:
        reminds['opises'] = json.loads(user.reminds_opises)
    else:
        reminds['opises'] = {}
    if user.reminds_deadlines:
        reminds['deadlines'] = json.loads(user.reminds_deadlines)
    else:
        reminds['deadlines'] = {}
    if user.reminds_statuses:
        reminds['statuses'] = json.loads(user.reminds_statuses)
    else:
        reminds['statuses'] = {}

    if user.photoprofile:
        photo = base64.b64encode(user.photoprofile).decode('utf-8')
    else:
        photo = None

    session.close()

    return flask.render_template('view_user.html',
                           user=user,
                           reminds=reminds,
                           photo_base64=photo,
                           is_admin=True)


@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return flask.redirect(flask.url_for('index'))

    session = db_session.create_session()
    user = session.query(User).get(user_id)

    if user and user.id != current_user.id and current_user.role != 'admin':
        session.delete(user)
        session.commit()
    session.close()
    return flask.redirect(flask.url_for('admin_users'))


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
