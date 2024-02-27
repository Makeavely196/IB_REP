import os
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QStackedWidget, QDialog, QDialogButtonBox, QInputDialog, QCheckBox
from PyQt5.QtWidgets import QMainWindow, QAction, QMenu
from PyQt5.QtWidgets import QComboBox, QPushButton
from PyQt5.QtCore import QTimer
from PyQt5.QtCore import Qt
import random
import string

class User:
    def __init__(self, username, password, is_admin=False, is_blocked=False, password_constraints_enabled=False):
        self.username = username
        self.password = password
        self.is_admin = is_admin
        self.is_blocked = is_blocked
        self.password_constraints_enabled = password_constraints_enabled

    def __str__(self):
        return f"Username: {self.username}, Admin: {self.is_admin}, Blocked: {self.is_blocked}"

def load_users_from_file(filename):
    users = []
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            for line in file:
                username, password, is_admin, is_blocked, constraints_enabled = line.strip().split(',')
                is_admin = is_admin.lower() == 'true'
                is_blocked = is_blocked.lower() == 'true'
                constraints_enabled = constraints_enabled.lower() == 'true'
                user = User(username, password, is_admin, is_blocked, constraints_enabled)
                users.append(user)
    else:
        # Если файла нет, создаем его
        with open(filename, 'w') as file:
            file.write("admin,,true,false,false\n")
        users = [User("admin", "", True, False, False)]

    return users
def save_users_to_file(filename, users):
    with open(filename, 'w') as file:
        for user in users:
            file.write(f"{user.username},{user.password},{str(user.is_admin).lower()},{str(user.is_blocked).lower()},{str(user.password_constraints_enabled).lower()}\n")

def authenticate(username, password, users):
    for user in users:
        if user.username == username and user.password == password:
            return user
    return None

class CreateUserForm(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Создать пользователя')

        self.username_label = QLabel('Логин:')
        self.username_input = QLineEdit()

        self.admin_checkbox = QCheckBox('Администратор')
        self.blocked_checkbox = QCheckBox('Заблокирован')
        self.constraints_checkbox = QCheckBox('Включить ограничения на пароль')

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.create_user)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.admin_checkbox)
        layout.addWidget(self.blocked_checkbox)
        layout.addWidget(self.constraints_checkbox)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def create_user(self):
        username = self.username_input.text()
        is_admin = self.admin_checkbox.isChecked()
        is_blocked = self.blocked_checkbox.isChecked()
        constraints_enabled = self.constraints_checkbox.isChecked()

        new_user = User(username, '', is_admin, is_blocked, constraints_enabled)
        main_window.users.append(new_user)
        save_users_to_file("users.txt", main_window.users)
        self.accept()

class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Сменить пароль')

        self.old_password_label = QLabel('Старый пароль:')
        self.old_password_input = QLineEdit()
        self.old_password_input.setEchoMode(QLineEdit.Password)

        self.new_password_label = QLabel('Новый пароль:')
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)

        self.repeat_password_label = QLabel('Повторите пароль:')
        self.repeat_password_input = QLineEdit()
        self.repeat_password_input.setEchoMode(QLineEdit.Password)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.change_password)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.old_password_label)
        layout.addWidget(self.old_password_input)
        layout.addWidget(self.new_password_label)
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.repeat_password_label)
        layout.addWidget(self.repeat_password_input)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def change_password(self):
        old_password = self.old_password_input.text()
        new_password = self.new_password_input.text()
        repeat_password = self.repeat_password_input.text()

        if main_window.current_user.password == old_password:
            if new_password == repeat_password:
                main_window.current_user.password = new_password
                save_users_to_file("users.txt", main_window.users)
                self.accept()
            else:
                QMessageBox.warning(self, 'Ошибка', 'Новые пароли не совпадают.')
        else:
            QMessageBox.warning(self, 'Ошибка', 'Старый пароль неверен.')

class NewPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Сменить пароль')

        self.new_password_label = QLabel('Новый пароль:')
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)

        self.repeat_password_label = QLabel('Повторите пароль:')
        self.repeat_password_input = QLineEdit()
        self.repeat_password_input.setEchoMode(QLineEdit.Password)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.change_password)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.new_password_label)
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.repeat_password_label)
        layout.addWidget(self.repeat_password_input)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def change_password(self):
        new_password = self.new_password_input.text()
        repeat_password = self.repeat_password_input.text()

        if new_password == repeat_password:
            main_window.current_user.password = new_password
            save_users_to_file("users.txt", main_window.users)
            self.accept()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Новые пароли не совпадают.')

class ViewUsersDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Просмотр пользователей')

        self.layout = QVBoxLayout(self)

        self.users = main_window.users

        # Создаем QComboBox для выбора пользователя
        self.user_combobox = QComboBox(self)
        self.user_combobox.addItems([user.username for user in self.users])
        self.user_combobox.currentIndexChanged.connect(self.update_selected_user)

        self.layout.addWidget(self.user_combobox)

        # Создаем чекбоксы для отображения и изменения параметров пользователя
        self.admin_checkbox = QCheckBox('Администратор', self)
        self.admin_checkbox.stateChanged.connect(self.update_user)
        self.layout.addWidget(self.admin_checkbox)

        self.blocked_checkbox = QCheckBox('Заблокирован', self)
        self.blocked_checkbox.stateChanged.connect(self.update_user)
        self.layout.addWidget(self.blocked_checkbox)

        self.constraints_checkbox = QCheckBox('Ограничения пароля', self)
        self.constraints_checkbox.stateChanged.connect(self.update_user)
        self.layout.addWidget(self.constraints_checkbox)

        self.setLayout(self.layout)

    def create_user_blocks(self):
        # Создаем блоки для каждого пользователя
        for user in self.users:
            user_block = QWidget(self)
            user_layout = QVBoxLayout(user_block)

            login_label = QLabel(f'Логин: {user.username}', user_block)

            # Создаем чекбоксы для каждого параметра пользователя
            admin_checkbox = QCheckBox('Администратор', user_block)
            admin_checkbox.setChecked(user.is_admin)
            admin_checkbox.stateChanged.connect(lambda state, u=user: self.update_user(u, is_admin=state == Qt.Checked))

            blocked_checkbox = QCheckBox('Заблокирован', user_block)
            blocked_checkbox.setChecked(user.is_blocked)
            blocked_checkbox.stateChanged.connect(lambda state, u=user: self.update_user(u, is_blocked=state == Qt.Checked))

            constraints_checkbox = QCheckBox('Ограничения пароля', user_block)
            constraints_checkbox.setChecked(user.password_constraints_enabled)
            constraints_checkbox.stateChanged.connect(lambda state, u=user: self.update_user(u, constraints_enabled=state == Qt.Checked))

            user_layout.addWidget(login_label)
            user_layout.addWidget(admin_checkbox)
            user_layout.addWidget(blocked_checkbox)
            user_layout.addWidget(constraints_checkbox)

            self.layout.addWidget(user_block)

        self.setLayout(self.layout)

    def update_selected_user(self, index):
        selected_user = self.users[index]
        # Обновление состояния чекбоксов в соответствии с выбранным пользователем
        self.admin_checkbox.setChecked(selected_user.is_admin)
        self.blocked_checkbox.setChecked(selected_user.is_blocked)
        self.constraints_checkbox.setChecked(selected_user.password_constraints_enabled)


    def update_user(self, user, is_admin=None, is_blocked=None, constraints_enabled=None):
        # Получение выбранного пользователя
        index = self.user_combobox.currentIndex()
        selected_user = self.users[index]

        # Обновление параметров выбранного пользователя
        selected_user.is_admin = self.admin_checkbox.isChecked()
        selected_user.is_blocked = self.blocked_checkbox.isChecked()
        selected_user.password_constraints_enabled = self.constraints_checkbox.isChecked()

        # Сохранение изменений в файл
        save_users_to_file("users.txt", main_window.users)

    def update_users_label(self):
        users_text = "\n".join([str(user) for user in main_window.users])
        self.users_label.setText(users_text)

class BlockUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Блокировать пользователя')

        self.username_label = QLabel('Логин:')
        self.username_input = QLineEdit()

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.block_user)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def block_user(self):
        username = self.username_input.text()
        user_to_block = next((user for user in main_window.users if user.username == username), None)

        if user_to_block:
            user_to_block.is_blocked = True
            save_users_to_file("users.txt", main_window.users)
            self.accept()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Пользователь не найден.')

class UnblockUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Разблокировать пользователя')

        self.username_label = QLabel('Логин:')
        self.username_input = QLineEdit()

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.unblock_user)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def unblock_user(self):
        username = self.username_input.text()
        user_to_unblock = next((user for user in main_window.users if user.username == username), None)

        if user_to_unblock:
            user_to_unblock.is_blocked = False
            save_users_to_file("users.txt", main_window.users)
            self.accept()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Пользователь не найден.')

class ToggleConstraintsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Включить/Отключить ограничения на пароль')

        self.enable_constraints_checkbox = QCheckBox('Включить ограничения')
        self.enable_constraints_checkbox.setChecked(main_window.password_constraints_enabled)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.toggle_constraints)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.enable_constraints_checkbox)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def toggle_constraints(self):
        main_window.password_constraints_enabled = self.enable_constraints_checkbox.isChecked()
        save_users_to_file("users.txt", main_window.users)
        self.accept()

class CreateFirstUserForm(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Создать первого пользователя')

        self.username_label = QLabel('Логин:')
        self.username_input = QLineEdit()

        self.password_label = QLabel('Пароль:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.repeat_password_label = QLabel('Повторите пароль:')
        self.repeat_password_input = QLineEdit()
        self.repeat_password_input.setEchoMode(QLineEdit.Password)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.create_first_user)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.repeat_password_label)
        layout.addWidget(self.repeat_password_input)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def create_first_user(self):
        username = self.username_input.text()
        password = self.password_input.text()
        repeat_password = self.repeat_password_input.text()

        if password == repeat_password:
            main_window.users.append(User(username, password, is_admin=True))
            save_users_to_file("users.txt", main_window.users)
            self.accept()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Пароли не совпадают.')

class CreateUserByAdminForm(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Создать пользователя администратором')

        self.username_label = QLabel('Логин:')
        self.username_input = QLineEdit()

        self.blocked_checkbox = QCheckBox('Заблокировать пользователя')
        self.constraints_checkbox = QCheckBox('Включить ограничения на пароль')

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.create_user)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.blocked_checkbox)
        layout.addWidget(self.constraints_checkbox)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def create_user(self):
        username = self.username_input.text()
        is_blocked = self.blocked_checkbox.isChecked()
        constraints_enabled = self.constraints_checkbox.isChecked()

        new_user = User(username, '', is_admin=False, is_blocked=is_blocked, password_constraints_enabled=constraints_enabled)
        main_window.users.append(new_user)
        save_users_to_file("users.txt", main_window.users)
        self.accept()

    def generate_and_display_password(self, user):
        password_length = 20  # You can adjust the length as needed
        characters = string.ascii_letters + string.digits + string.punctuation
        new_password = ''.join(random.choice(characters) for i in range(password_length))
        QMessageBox.information(self, 'Сгенерированный пароль', f'Сгенерированный пароль для пользователя {user.username}:\n\n{new_password}')

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.users = load_users_from_file("users.txt")
        self.current_user = None
        self.password_constraints_enabled = False
        self.login_attempts = 0
        self.max_login_attempts = 3

        self.init_ui()

    def init_ui(self):
        auth_widget = QWidget(self)

        auth_layout = QVBoxLayout(auth_widget)

        auth_label = QLabel('Авторизация', auth_widget)
        auth_layout.addWidget(auth_label)

        auth_username_label = QLabel('Логин:', auth_widget)
        self.auth_username_input = QLineEdit(auth_widget)
        auth_layout.addWidget(auth_username_label)
        auth_layout.addWidget(self.auth_username_input)

        auth_password_label = QLabel('Пароль:', auth_widget)
        self.auth_password_input = QLineEdit(auth_widget)
        self.auth_password_input.setEchoMode(QLineEdit.Password)
        auth_layout.addWidget(auth_password_label)
        auth_layout.addWidget(self.auth_password_input)

        auth_button = QPushButton('Войти', auth_widget)
        auth_button.clicked.connect(self.authenticate_user)
        auth_layout.addWidget(auth_button)

        self.stacked_widget = QStackedWidget()

        user_panel_widget = QWidget(self)

        self.login_label = QLabel(self)
        change_password_button = QPushButton('Сменить пароль', user_panel_widget)
        change_password_button.clicked.connect(self.show_change_password)

        self.view_users_button = QPushButton('Просмотр пользователей', user_panel_widget)
        self.view_users_button.clicked.connect(self.view_users)
        self.view_users_button.setEnabled(False)

        # self.block_user_button = QPushButton('Блокировать пользователя', user_panel_widget)
        # self.block_user_button.clicked.connect(self.block_user)
        # self.block_user_button.setEnabled(False)

        # self.unblock_user_button = QPushButton('Разблокировать пользователя', user_panel_widget)
        # self.unblock_user_button.clicked.connect(self.unblock_user)
        # self.unblock_user_button.setEnabled(False)

        # self.toggle_constraints_button = QPushButton('Включить/Отключить ограничения', user_panel_widget)
        # self.toggle_constraints_button.clicked.connect(self.toggle_constraints)
        # self.toggle_constraints_button.setEnabled(False)

        self.logout_button = QPushButton('Выйти', user_panel_widget)
        self.logout_button.clicked.connect(self.logout)

        self.create_user_button = QPushButton('Создать пользователя', user_panel_widget)
        self.create_user_button.clicked.connect(self.show_create_user_form)
        self.create_user_button.setEnabled(False)

        user_layout = QVBoxLayout(user_panel_widget)
        user_layout.addWidget(self.login_label)
        user_layout.addWidget(change_password_button)
        user_layout.addWidget(self.view_users_button)
        # user_layout.addWidget(self.block_user_button)
        # user_layout.addWidget(self.unblock_user_button)
        # user_layout.addWidget(self.toggle_constraints_button)
        user_layout.addWidget(self.create_user_button)
        user_layout.addWidget(self.logout_button)

        auth_widget.setStyleSheet("background-color: lightblue;")
        user_panel_widget.setStyleSheet("background-color: lightgreen;")

        self.stacked_widget.addWidget(auth_widget)
        self.stacked_widget.addWidget(user_panel_widget)

        self.setCentralWidget(self.stacked_widget)

        self.setGeometry(300, 300, 400, 300)
        self.setWindowTitle('Система управления пользователями')

    def init_user_panel(self):
        self.auth_username_input.clear()
        self.auth_password_input.clear()
        self.login_attempts = 0

        if self.current_user and self.current_user.is_blocked:
            QMessageBox.warning(self, 'Блокировка', 'Ваша учетная запись заблокирована. Обратитесь к администратору.')
            self.current_user = None
            self.stacked_widget.setCurrentIndex(0)  # Переключение на форму авторизации
        elif self.current_user and not self.current_user.password:
            self.show_change_new_password()
        else:
            self.update_user_panel()
            self.stacked_widget.setCurrentIndex(1)  # Переключение на форму пользователя или администратора

    def authenticate_user(self):
        username = self.auth_username_input.text()
        password = self.auth_password_input.text()

        self.current_user = authenticate(username, password, self.users)

        if self.current_user:
            self.init_user_panel()
        else:
            self.login_attempts += 1
            if self.login_attempts >= self.max_login_attempts:
                QMessageBox.critical(self, 'Ошибка', 'Превышено количество попыток входа. Программа будет закрыта.')
                self.close()
            else:
                QMessageBox.warning(self, 'Ошибка', 'Неверные логин или пароль.')
            
            self.logout()

    def update_user_panel(self):
        if self.current_user and not self.current_user.is_blocked:
            self.login_label.setText(f"Вы вошли как {'администратор' if self.current_user.is_admin else 'пользователь'}: {self.current_user.username}")
            self.view_users_button.show() if self.current_user.is_admin else self.view_users_button.hide()
            # self.block_user_button.show() if self.current_user.is_admin else self.block_user_button.hide()
            # self.unblock_user_button.show() if self.current_user.is_admin else self.unblock_user_button.hide()
            # self.toggle_constraints_button.show() if self.current_user.is_admin else self.toggle_constraints_button.hide()
            self.create_user_button.show() if self.current_user.is_admin else self.create_user_button.hide()
            self.view_users_button.setEnabled(True) if self.current_user.is_admin else self.view_users_button.hide()
            # self.block_user_button.setEnabled(True) if self.current_user.is_admin else self.block_user_button.hide()
            # self.unblock_user_button.setEnabled(True) if self.current_user.is_admin else self.unblock_user_button.hide()
            # self.toggle_constraints_button.setEnabled(True) if self.current_user.is_admin else self.toggle_constraints_button.hide()
            self.create_user_button.setEnabled(True) if self.current_user.is_admin else self.create_user_button.hide()
        elif self.current_user and self.current_user.is_blocked:
            self.login_label.setText(f"Пользователь {self.current_user.username} заблокирован.")
            self.view_users_button.hide()
            # self.block_user_button.hide()
            # self.unblock_user_button.hide()
            # self.toggle_constraints_button.hide()
            self.create_user_button.hide()
        else:
            self.login_label.clear()

    def show_change_password(self):
        if self.current_user:
            change_password_dialog = ChangePasswordDialog(self)
            change_password_dialog.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Пользователь не авторизован.')
            
    def show_change_new_password(self):
        if self.current_user:
            change_password_dialog = NewPasswordDialog(self)
            change_password_dialog.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Пользователь не авторизован.')

    def view_users(self):
        if self.current_user and self.current_user.is_admin:
            view_users_dialog = ViewUsersDialog(self)
            view_users_dialog.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Доступно только для администратора.')

    def block_user(self):
        if self.current_user and self.current_user.is_admin:
            block_user_dialog = BlockUserDialog(self)
            block_user_dialog.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Доступно только для администратора.')

    def unblock_user(self):
        if self.current_user and self.current_user.is_admin:
            unblock_user_dialog = UnblockUserDialog(self)
            unblock_user_dialog.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Доступно только для администратора.')

    def toggle_constraints(self):
        if self.current_user and self.current_user.is_admin:
            toggle_constraints_dialog = ToggleConstraintsDialog(self)
            toggle_constraints_dialog.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Доступно только для администратора.')

    def show_create_user_form(self):
        if self.current_user and self.current_user.is_admin:
            create_user_form = CreateUserByAdminForm(self)
            create_user_form.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Доступно только для администратора.')

    def logout(self):
        self.current_user = None
        self.stacked_widget.setCurrentIndex(0)  # Переключение на форму авторизации
        self.auth_username_input.clear()
        self.auth_password_input.clear()
        self.login_label.clear()
        self.update_user_panel()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
