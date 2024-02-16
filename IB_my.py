import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QStackedWidget, QDialog, QDialogButtonBox

class User:
    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.password = password
        self.is_admin = is_admin

    def __str__(self):
        return f"Username: {self.username}, Admin: {self.is_admin}"

def load_users_from_file(filename):
    users = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                username, password, is_admin = line.strip().split(',')
                users.append(User(username, password, is_admin.lower() == 'true'))
    except FileNotFoundError:
        pass
    return users

def save_users_to_file(filename, users):
    with open(filename, 'w') as file:
        for user in users:
            file.write(f"{user.username},{user.password},{str(user.is_admin).lower()}\n")

def authenticate(username, password, users):
    for user in users:
        if user.username == username and user.password == password:
            return user
    return None

class ChangePasswordDialog(QDialog):
    def __init__(self, current_user, users, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Смена пароля')
        self.current_user = current_user
        self.users = users

        self.old_password_label = QLabel('Старый пароль:')
        self.old_password_input = QLineEdit()
        self.new_password_label = QLabel('Новый пароль:')
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(self.old_password_label)
        layout.addWidget(self.old_password_input)
        layout.addWidget(self.new_password_label)
        layout.addWidget(self.new_password_input)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def accept(self):
        old_password = self.old_password_input.text()
        new_password = self.new_password_input.text()

        if old_password == self.current_user.password:
            self.current_user.password = new_password
            save_users_to_file("users.txt", self.users)
            QMessageBox.information(self, 'Успех', 'Пароль успешно изменен.')
            super().accept()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Неверный старый пароль.')

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.users = load_users_from_file("users.txt")
        self.current_user = None

        self.stacked_widget = QStackedWidget(self)

        self.init_login_form()
        self.init_user_panel()

        layout = QVBoxLayout(self)
        layout.addWidget(self.stacked_widget)

    def init_login_form(self):
        login_widget = QWidget(self)

        username_label = QLabel('Логин:')
        username_input = QLineEdit()

        password_label = QLabel('Пароль:')
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)

        login_button = QPushButton('Войти')
        login_button.clicked.connect(lambda: self.on_login(username_input.text(), password_input.text()))

        layout = QVBoxLayout(login_widget)
        layout.addWidget(username_label)
        layout.addWidget(username_input)
        layout.addWidget(password_label)
        layout.addWidget(password_input)
        layout.addWidget(login_button)

        self.stacked_widget.addWidget(login_widget)

    def init_user_panel(self):
        user_panel_widget = QWidget(self)

        self.login_label = QLabel(self)
        change_password_button = QPushButton('Сменить пароль', self)
        change_password_button.clicked.connect(self.show_change_password)
        
        # Добавлена кнопка для администратора и кнопка выхода
        self.view_users_button = QPushButton('Просмотр пользователей', self)
        self.view_users_button.clicked.connect(self.view_users)
        self.view_users_button.setEnabled(False)
        
        logout_button = QPushButton('Выйти', self)
        logout_button.clicked.connect(self.logout)

        layout = QVBoxLayout(user_panel_widget)
        layout.addWidget(self.login_label)
        layout.addWidget(change_password_button)
        
        # Добавлена кнопка для администратора и кнопка выхода
        layout.addWidget(self.view_users_button)
        layout.addWidget(logout_button)

        self.stacked_widget.addWidget(user_panel_widget)

    def on_login(self, input_username, input_password):
        authenticated_user = authenticate(input_username, input_password, self.users)

        if authenticated_user:
            self.current_user = authenticated_user
            self.stacked_widget.setCurrentIndex(1)
            self.update_user_panel()
        else:
            self.show_message("Ошибка аутентификации. Пользователь не найден или неверный пароль.")

    def show_change_password(self):
        dialog = ChangePasswordDialog(self.current_user, self.users, self)
        dialog.exec_()

    def view_users(self):
        user_list = '\n'.join(str(user) for user in self.users)
        QMessageBox.information(self, 'Список пользователей', user_list)

    def logout(self):
        self.stacked_widget.setCurrentIndex(0)

    def update_user_panel(self):
        self.login_label.setText(f'Вы вошли как: {self.current_user.username}')
        
        # Активируем кнопку "Просмотр пользователей" только для администратора
        if self.current_user.is_admin:
            self.view_users_button.setEnabled(True)
        else:
            self.view_users_button.setEnabled(False)

    def show_message(self, message):
        msg_box = QMessageBox()
        msg_box.setText(message)
        msg_box.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
