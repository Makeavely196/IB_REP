import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QStackedWidget, QDialog, QDialogButtonBox, QInputDialog, QCheckBox, QMainWindow, QAction, QMenu

class User:
    def __init__(self, username, password, is_admin=False, is_blocked=False):
        self.username = username
        self.password = password
        self.is_admin = is_admin
        self.is_blocked = is_blocked

    def __str__(self):
        return f"Username: {self.username}, Admin: {self.is_admin}, Blocked: {self.is_blocked}"

def load_users_from_file(filename):
    users = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                username, password, is_admin, is_blocked = line.strip().split(',')
                users.append(User(username, password, is_admin.lower() == 'true', is_blocked.lower() == 'true'))
    except FileNotFoundError:
        pass
    return users

def save_users_to_file(filename, users):
    with open(filename, 'w') as file:
        for user in users:
            file.write(f"{user.username},{user.password},{str(user.is_admin).lower()},{str(user.is_blocked).lower()}\n")

def authenticate(username, password, users):
    for user in users:
        if user.username == username and user.password == password and not user.is_blocked:
            return user
    return None

class ChangePasswordDialog(QDialog):
    def __init__(self, current_user, users, password_constraints_enabled, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Смена пароля')
        self.current_user = current_user
        self.users = users
        self.password_constraints_enabled = password_constraints_enabled

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

        if self.password_constraints_enabled:
            if not any(char.isdigit() for char in new_password):
                QMessageBox.warning(self, 'Ошибка', 'Пароль должен содержать хотя бы одну цифру.')
                return

            if not any(char in '!@#$%^&*()-_=+[]{}|;:\'",.<>/?`~' for char in new_password):
                QMessageBox.warning(self, 'Ошибка', 'Пароль должен содержать хотя бы один знак препинания или арифметический оператор.')
                return

        if old_password == self.current_user.password:
            self.current_user.password = new_password
            save_users_to_file("users.txt", self.users)
            QMessageBox.information(self, 'Успех', 'Пароль успешно изменен.')
            super().accept()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Неверный старый пароль.')

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.users = load_users_from_file("users.txt")
        self.current_user = None
        self.password_constraints_enabled = False
        self.failed_attempts = 0  # Счетчик неудачных попыток
        self.max_failed_attempts = 3  # Предельное значение неудачных попыток

        self.stacked_widget = QStackedWidget(self)

        self.init_login_form()
        self.init_user_panel()

        self.setCentralWidget(self.stacked_widget)

        # Добавляем меню
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu('Файл')

        # Подменю "Справка" с командой "О программе"
        help_menu = menu_bar.addMenu('Справка')
        about_action = QAction('О программе', self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

    def show_about_dialog(self):
        QMessageBox.about(self, 'О программе', 'Савельев Антон, ИДБ-20-07, 18 вариант')

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
        
        # Добавлена кнопка для администратора и кнопка выхода
        self.block_user_button = QPushButton('Блокировать пользователя', self)
        self.block_user_button.clicked.connect(self.block_user)
        self.block_user_button.setEnabled(False)
        
        # Добавлена кнопка для администратора и кнопка выхода
        self.unblock_user_button = QPushButton('Разблокировать пользователя', self)
        self.unblock_user_button.clicked.connect(self.unblock_user)
        self.unblock_user_button.setEnabled(False)

        # Добавлена кнопка для администратора и кнопка выхода
        self.toggle_constraints_button = QPushButton('Включить/Отключить ограничения', self)
        self.toggle_constraints_button.clicked.connect(self.toggle_constraints)
        self.toggle_constraints_button.setEnabled(False)
        
        logout_button = QPushButton('Выйти', self)
        logout_button.clicked.connect(self.logout)

        layout = QVBoxLayout(user_panel_widget)
        layout.addWidget(self.login_label)
        layout.addWidget(change_password_button)
        
        # Добавлена кнопка для администратора и кнопка выхода
        layout.addWidget(self.view_users_button)
        layout.addWidget(self.block_user_button)
        layout.addWidget(self.unblock_user_button)
        layout.addWidget(self.toggle_constraints_button)
        layout.addWidget(logout_button)

        self.stacked_widget.addWidget(user_panel_widget)

    def on_login(self, input_username, input_password):
        authenticated_user = authenticate(input_username, input_password, self.users)

        if authenticated_user:
            if authenticated_user.is_blocked:
                QMessageBox.warning(self, 'Ошибка входа', 'Ваша учетная запись заблокирована.')
            else:
                self.current_user = authenticated_user
                self.failed_attempts = 0  # Сбрасываем счетчик при успешном входе
                self.stacked_widget.setCurrentIndex(1)
                self.update_user_panel()
        else:
            self.failed_attempts += 1  # Увеличиваем счетчик неудачных попыток
            self.show_message(f"Ошибка аутентификации. Попытка {self.failed_attempts} из {self.max_failed_attempts}."
                              " Пользователь не найден или неверный пароль.")

            if self.failed_attempts >= self.max_failed_attempts:
                self.close()  # Закрываем программу при достижении предельного значения неудачных попыток

    def show_change_password(self):
        dialog = ChangePasswordDialog(self.current_user, self.users, self.password_constraints_enabled, self)
        dialog.exec_()

    def view_users(self):
        user_list = '\n'.join(str(user) for user in self.users)
        QMessageBox.information(self, 'Список пользователей', user_list)

    def block_user(self):
        users_to_select = [user.username for user in self.users if not user.is_admin and not user.is_blocked]
        selected_user, ok = QInputDialog.getItem(self, 'Выбор пользователя', 'Выберите пользователя:', users_to_select, editable=False)

        if ok and selected_user:
            user_to_block = next(user for user in self.users if user.username == selected_user)
            
            if user_to_block.is_blocked:
                QMessageBox.information(self, 'Блокировка пользователя', f'Пользователь {selected_user} уже заблокирован.')
            else:
                user_to_block.is_blocked = True
                save_users_to_file("users.txt", self.users)
                
                if self.current_user and self.current_user.username == selected_user:
                    QMessageBox.warning(self, 'Блокировка учетной записи', 'Ваша учетная запись была заблокирована. Выход из системы.')
                    self.logout()
                else:
                    QMessageBox.information(self, 'Блокировка пользователя', f'Пользователь {selected_user} заблокирован.')

    def unblock_user(self):
        users_to_select = [user.username for user in self.users if not user.is_admin and user.is_blocked]
        selected_user, ok = QInputDialog.getItem(self, 'Выбор пользователя', 'Выберите пользователя:', users_to_select, editable=False)

        if ok and selected_user:
            user_to_unblock = next(user for user in self.users if user.username == selected_user)
            
            if not user_to_unblock.is_blocked:
                QMessageBox.information(self, 'Разблокировка пользователя', f'Пользователь {selected_user} уже разблокирован.')
            else:
                user_to_unblock.is_blocked = False
                save_users_to_file("users.txt", self.users)
                QMessageBox.information(self, 'Разблокировка пользователя', f'Пользователь {selected_user} разблокирован.')

    def toggle_constraints(self):
        self.password_constraints_enabled = not self.password_constraints_enabled
        QMessageBox.information(self, 'Ограничения пароля', f"Ограничения пароля {'включены' if self.password_constraints_enabled else 'отключены'}.")

    def logout(self):
        self.stacked_widget.setCurrentIndex(0)

    def update_user_panel(self):
        self.login_label.setText(f'Вы вошли как: {self.current_user.username}')
        
        # Активируем кнопку "Просмотр пользователей" только для администратора
        if self.current_user.is_admin:
            self.view_users_button.setEnabled(True)
            self.block_user_button.setEnabled(True)  # Активируем кнопку блокировки для администратора
            self.unblock_user_button.setEnabled(True)  # Активируем кнопку разблокировки для администратора
            self.toggle_constraints_button.setEnabled(True)  # Активируем кнопку включения/отключения ограничений
        else:
            self.view_users_button.setEnabled(False)
            self.block_user_button.setEnabled(False)  # Деактивируем кнопку блокировки для обычного пользователя
            self.unblock_user_button.setEnabled(False)  # Деактивируем кнопку разблокировки для обычного пользователя
            self.toggle_constraints_button.setEnabled(False)  # Деактивируем кнопку включения/отключения ограничений

    def show_message(self, message):
        msg_box = QMessageBox()
        msg_box.setText(message)
        msg_box.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
