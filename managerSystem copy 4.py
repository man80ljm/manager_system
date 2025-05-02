import sys
import sqlite3
from datetime import datetime
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QScrollArea,
                             QLineEdit, QDialog, QMessageBox, QFormLayout,
                             QInputDialog, QTableWidget, QTableWidgetItem, 
                             QCheckBox,QListWidget,QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QTimer
from PyQt5.QtGui import QIcon
import hashlib
from datetime import datetime

# 注册 sqlite3 的 datetime 适配器和转换器
def adapt_datetime(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def convert_datetime(s):
    s = s.decode('utf-8') if isinstance(s, bytes) else s
    try:
        # 尝试解析不含微秒的格式
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        # 如果失败，尝试解析含微秒的格式
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("DATETIME", convert_datetime)

# 检查依赖
try:
    from PyQt5.QtWidgets import QApplication
    import pandas as pd
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请安装所需库: pip install PyQt5 pandas")
    sys.exit(1)

# 数据库初始化
def init_db():
    conn = sqlite3.connect('shop_system.db', detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()

    cursor.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='users' ''')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'staff',
                last_failed_attempt INTEGER DEFAULT 0,
                attempt_count INTEGER DEFAULT 0,
                balance REAL DEFAULT 0
            )
        ''')
        admin_hash = hashlib.sha256("hyyf123".encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, balance)
            VALUES (?, ?, ?, ?)
        ''', ('hyyf', admin_hash, 'admin', 0.0))

    cursor.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='transactions' ''')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            CREATE TABLE transactions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                type TEXT,
                amount REAL,
                category TEXT,
                timestamp DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_trans_user ON transactions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_trans_time ON transactions(timestamp)")

    conn.commit()
    conn.close()

class LoginWindow(QDialog):
    MAX_ATTEMPTS = 3
    LOCK_TIME = 30

    def __init__(self):
        super().__init__()
        # 设置窗口标志，移除帮助按钮
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setWindowTitle("安全登录")
        self.setFixedSize(550, 450)
        self.attempts = 0
        self.locked = False
        self.settings = QSettings("MyCompany", "ShopSystem")
        self.init_ui()
        self.load_saved_credentials()

    def init_ui(self):
        main_layout = QVBoxLayout()  # 直接使用 QVBoxLayout 作为主布局

        title = QLabel('用户消费记账系统')
        title.setStyleSheet('font-size: 36px; font-weight: bold;')
        main_layout.addWidget(title)

        # 用户名输入
        self.username_input = QLineEdit()
        main_layout.addWidget(QLabel("用户名:"))
        main_layout.addWidget(self.username_input)

        # 密码输入
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        main_layout.addWidget(QLabel("密码:"))
        main_layout.addWidget(self.password_input)

        # 记住我选项
        self.remember_check = QCheckBox("记住我")
        main_layout.addWidget(self.remember_check)

        # 按钮布局
        btn_layout = QHBoxLayout()
        self.btn_login = QPushButton('登录')
        self.btn_login.clicked.connect(self.attempt_login)
        btn_layout.addWidget(self.btn_login)

        self.btn_reset = QPushButton('重置密码')
        self.btn_reset.clicked.connect(self.show_password_reset)
        btn_layout.addWidget(self.btn_reset)

        main_layout.addLayout(btn_layout)

        # 将布局直接设置为对话框的布局
        self.setLayout(main_layout)

        

    def load_saved_credentials(self):
        username = self.settings.value("username", "")
        password = self.settings.value("password", "")
        remember = self.settings.value("remember", "false") == "true"
        if username and remember:
            self.username_input.setText(username)
            self.password_input.setText(password)
            self.remember_check.setChecked(True)

    def save_credentials(self):
        if self.remember_check.isChecked():
            self.settings.setValue("username", self.username_input.text())
            self.settings.setValue("password", self.password_input.text())
            self.settings.setValue("remember", "true")
        else:
            self.settings.remove("password")
            self.settings.setValue("remember", "false")

    def attempt_login(self):
        if self.locked:
            QMessageBox.warning(self, "账户锁定", f"账户已锁定，请{self.LOCK_TIME}秒后再试")
            return

        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "输入错误", "用户名和密码不能为空")
            return

        if self.verify_credentials(username, password):
            self.save_credentials()
            self.accept()
        else:
            self.attempts += 1
            remaining = self.MAX_ATTEMPTS - self.attempts
            if remaining > 0:
                QMessageBox.warning(self, "登录失败", f"用户名或密码错误，剩余尝试次数: {remaining}")
            else:
                self.lock_account()
                QMessageBox.critical(self, "账户锁定", f"超过最大尝试次数，账户已锁定{self.LOCK_TIME}秒")

    def verify_credentials(self, username, password):
        with sqlite3.connect('shop_system.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT password_hash, attempt_count, last_failed_attempt 
                FROM users WHERE username=?
            ''', (username,))
            result = cursor.fetchone()

            if not result:
                return False

            stored_hash, attempts, last_attempt = result
            input_hash = hashlib.sha256(password.encode()).hexdigest()

            if attempts >= self.MAX_ATTEMPTS:
                current_time = int(datetime.now().timestamp())
                if current_time - last_attempt < self.LOCK_TIME:
                    self.locked = True
                    return False
                else:
                    cursor.execute('UPDATE users SET attempt_count=0 WHERE username=?', (username,))
                    conn.commit()

            if stored_hash == input_hash:
                cursor.execute('UPDATE users SET attempt_count=0 WHERE username=?', (username,))
                conn.commit()
                return True
            else:
                cursor.execute('''
                    UPDATE users 
                    SET attempt_count=attempt_count+1, 
                        last_failed_attempt=? 
                    WHERE username=?
                ''', (int(datetime.now().timestamp()), username))
                conn.commit()
                return False

    def lock_account(self):
        self.locked = True
        QTimer.singleShot(self.LOCK_TIME * 1000, self.unlock_account)

    def unlock_account(self):
        self.locked = False
        self.attempts = 0
        QMessageBox.information(self, "账户解锁", "您可以重新尝试登录")

    def show_password_reset(self):
        email, ok = QInputDialog.getText(self, "重置密码", "请输入注册邮箱:")
        if ok and email:
            QMessageBox.information(self, "已发送", "重置链接已发送到您的邮箱（模拟）")


class AsyncLoader(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, query, params=()):
        super().__init__()
        self.query = query
        self.params = params

    def run(self):
        try:
            with sqlite3.connect('shop_system.db') as conn:
                cursor = conn.cursor()
                cursor.execute(self.query, self.params)
                self.finished.emit(cursor.fetchall())
        except Exception as e:
            self.error.emit(str(e))

class AddUserDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('新增用户')
        layout = QFormLayout()
        self.name_input = QLineEdit()
        layout.addRow('用户名:', self.name_input)
        btn_confirm = QPushButton('确定')
        btn_confirm.clicked.connect(self.accept)
        layout.addRow(btn_confirm)
        self.setLayout(layout)

class DetailWindow(QWidget):
    # 定义信号，用于通知主窗口刷新
    balance_updated = pyqtSignal()

    def __init__(self, user_id, parent=None):
        super().__init__(flags=Qt.Window)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.user_id = user_id
        self.parent = parent

        # 检查是否为 hyyf
        with sqlite3.connect('shop_system.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE id=?", (self.user_id,))
            username = cursor.fetchone()[0]
            if username == 'hyyf':
                QMessageBox.information(self, "提示", "超级管理员！")
                self.close()  # 关闭详情窗口
                return

        self.init_ui()
        self.load_data()

    def init_ui(self):
        layout = QVBoxLayout()
        self.lbl_info = QLabel()
        layout.addWidget(self.lbl_info)

        btn_layout = QHBoxLayout()
        self.btn_topup = QPushButton('充值')
        self.btn_consume = QPushButton('消费')
        self.btn_back = QPushButton('返回')
        btn_layout.addWidget(self.btn_topup)
        btn_layout.addWidget(self.btn_consume)
        btn_layout.addWidget(self.btn_back)
        layout.addLayout(btn_layout)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["时间", "类型", "金额", "类目"])
        layout.addWidget(self.table)

        self.lbl_summary = QLabel()
        layout.addWidget(self.lbl_summary)

        self.setLayout(layout)

        # 或者设置最小尺寸
        self.setMinimumSize(1250, 600)  # 设置最小宽度为 1250 像素，高度为 600 像素

        self.btn_topup.clicked.connect(self.on_topup_clicked)
        self.btn_consume.clicked.connect(self.on_consume_clicked)
        self.btn_back.clicked.connect(self.close)

    def load_data(self):
        with sqlite3.connect('shop_system.db', detect_types=sqlite3.PARSE_DECLTYPES) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, balance FROM users WHERE id=?", (self.user_id,))
            result = cursor.fetchone()
            if result:
                username, balance = result
                self.lbl_info.setText(f"用户信息: {username} (ID: {self.user_id}) 余额: ¥{balance:.2f}")

            cursor.execute("""
                SELECT timestamp, type, amount, category 
                FROM transactions 
                WHERE user_id=? 
                ORDER BY timestamp DESC
            """, (self.user_id,))
            transactions = cursor.fetchall()

            self.table.setRowCount(len(transactions))
            for row, (timestamp, trans_type, amount, category) in enumerate(transactions):
                # timestamp 现在是 datetime 对象，直接格式化
                formatted_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                # 创建并设置居中的表格项
                time_item = QTableWidgetItem(formatted_timestamp)
                time_item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, 0, time_item)

                type_item = QTableWidgetItem(trans_type)
                type_item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, 1, type_item)

                amount_item = QTableWidgetItem(f"{amount:.2f}")
                amount_item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, 2, amount_item)

                category_item = QTableWidgetItem(category)
                category_item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, 3, category_item)

            # 自动调整列宽以适应内容
            self.table.resizeColumnsToContents()

            # 为每列增加额外的宽度（模拟 2 个字符的间距）
            font_metrics = self.table.fontMetrics()
            char_width = font_metrics.averageCharWidth()  # 获取单个字符的平均宽度
            extra_padding = char_width * 12  # 两边各 2 个字符宽度（左右共 4 个字符）

            for col in range(self.table.columnCount()):
                current_width = self.table.columnWidth(col)
                self.table.setColumnWidth(col, current_width + extra_padding)

            total_income = sum(t[2] for t in transactions if t[1] == 'topup')
            total_expense = sum(t[2] for t in transactions if t[1] == 'consumption')
            self.lbl_summary.setText(f"总收入: ¥{total_income:.2f} 总支出: ¥{total_expense:.2f}")

    def on_topup_clicked(self):
        amount, ok = QInputDialog.getDouble(self, '充值', '输入充值金额:', 0, 0, 1000000, 2)
        if ok and amount > 0:
            self.save_transaction('topup', amount, '充值')

    def on_consume_clicked(self):
        with sqlite3.connect('shop_system.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT balance FROM users WHERE id=?", (self.user_id,))
            balance = cursor.fetchone()[0]

        amount, ok = QInputDialog.getDouble(self, '消费', '输入消费金额:', 0, 0, balance, 2)
        if not ok or amount <= 0:
            return

        if amount > balance:
            QMessageBox.warning(self, "余额不足", f"当前余额: ¥{balance:.2f}，不足以支付 ¥{amount:.2f}")
            return

        category, ok = QInputDialog.getText(self, '消费类目', '请输入消费类目:')
        if not ok or not category.strip():
            QMessageBox.warning(self, "输入错误", "消费类目不能为空")
            return

        self.save_transaction('consumption', amount, category.strip())

    def save_transaction(self, trans_type, amount, category):
        with sqlite3.connect('shop_system.db', detect_types=sqlite3.PARSE_DECLTYPES) as conn:
            cursor = conn.cursor()
            if trans_type == 'topup':
                cursor.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, self.user_id))
            else:
                cursor.execute("SELECT balance FROM users WHERE id=?", (self.user_id,))
                balance = cursor.fetchone()[0]
                if amount > balance:
                    QMessageBox.warning(self, "余额不足", f"当前余额: ¥{balance:.2f}，不足以支付 ¥{amount:.2f}")
                    return
                cursor.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, self.user_id))
            # 去掉微秒
            timestamp = datetime.now().replace(microsecond=0)
            cursor.execute('''
                INSERT INTO transactions (user_id, type, amount, category, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (self.user_id, trans_type, amount, category, timestamp))
            conn.commit()
            self.load_data()
            self.balance_updated.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_page = 1
        self.init_ui()
        self.refresh_users()
    #搜索用户
    def search_user(self):
        search_text = self.search_input.text().strip()
        if not search_text:
            QMessageBox.warning(self, "输入错误", "请输入用户名或ID")
            return

        # 查询数据库
        with sqlite3.connect('shop_system.db') as conn:
            cursor = conn.cursor()
            query = '''
                SELECT id FROM users 
                WHERE id = ? OR username LIKE ?
            '''
            try:
                search_id = int(search_text) if search_text.isdigit() else -1
                cursor.execute(query, (search_id, f'%{search_text}%'))
                result = cursor.fetchone()
            except ValueError:
                cursor.execute(query, (-1, f'%{search_text}%'))
                result = cursor.fetchone()

            if result:
                user_id = result[0]
                self.search_input.clear()  # 清空搜索框
                self.suggestion_list.hide()  # 隐藏建议列表
                self.show_detail(user_id)  # 打开用户详情
            else:
                QMessageBox.warning(self, "无此用户", f"未找到用户: {search_text}")

    def init_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        # 顶部布局：标题 + 搜索框
        top_layout = QHBoxLayout()
        title = QLabel('用户消费记账系统')
        title.setStyleSheet('font-size: 30px; font-weight: bold;')
        top_layout.addWidget(title)

        # 添加搜索框
        top_layout.addStretch()  # 左侧填充空白，将搜索框推到右边
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("输入用户名或ID搜索")
        self.search_input.setFixedWidth(300)  # 设置搜索框宽度
        self.search_input.setStyleSheet("border: 1px solid gray; border-radius: 5px; padding: 2px;")
        self.search_input.textChanged.connect(self.update_search_suggestions)  # 文本变化时更新建议
        top_layout.addWidget(self.search_input)

        # 搜索按钮（可选，保留以支持回车搜索）
        self.btn_search = QPushButton('搜索')
        self.btn_search.clicked.connect(self.search_user)  # 搜索按钮触发搜索
        top_layout.addWidget(self.btn_search)

        main_layout.addLayout(top_layout)

        # 添加建议列表（初始隐藏）
        self.suggestion_list = QListWidget()
        self.suggestion_list.setFixedWidth(600)  # 与搜索框宽度一致
        self.suggestion_list.hide()  # 初始隐藏
        self.suggestion_list.itemClicked.connect(self.on_suggestion_clicked)  # 点击建议项时跳转
        # 添加样式
        self.suggestion_list.setStyleSheet("""
            QListWidget {
                border: 1px solid gray;
                border-radius: 5px;
            }
            QListWidget::item:hover {
                background-color: #e0e0e0;
            }
        """)
        self.suggestion_list.setMaximumHeight(150)  # 限制高度为 150 像素
        main_layout.addWidget(self.suggestion_list)

        # 其余布局保持不变
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.user_container = QWidget()
        self.user_layout = QVBoxLayout()
        self.user_container.setLayout(self.user_layout)
        self.scroll_area.setWidget(self.user_container)
        main_layout.addWidget(self.scroll_area)

        btn_layout = QHBoxLayout()
        self.btn_add = QPushButton('创建用户')
        self.btn_revenue = QPushButton('营收情况')
        self.btn_import = QPushButton('导入Excel')
        self.btn_export = QPushButton('导出Excel')
        btn_layout.addWidget(self.btn_add)
        btn_layout.addWidget(self.btn_revenue)
        btn_layout.addWidget(self.btn_import)
        btn_layout.addWidget(self.btn_export)
        main_layout.addLayout(btn_layout)

        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.btn_add.clicked.connect(self.add_user)
        self.btn_revenue.clicked.connect(self.show_revenue)
        self.btn_import.clicked.connect(self.import_from_excel)
        self.btn_export.clicked.connect(self.export_to_excel)
    
    #用户输入时实时查询数据库
    def update_search_suggestions(self):
        search_text = self.search_input.text().strip()
        
        # 如果输入为空，隐藏建议列表
        if not search_text:
            self.suggestion_list.hide()
            return

        # 查询数据库，模糊匹配用户
        with sqlite3.connect('shop_system.db') as conn:
            cursor = conn.cursor()
            query = '''
                SELECT id, username FROM users 
                WHERE id = ? OR username LIKE ?
            '''
            try:
                search_id = int(search_text) if search_text.isdigit() else -1
                cursor.execute(query, (search_id, f'%{search_text}%'))
                results = cursor.fetchall()
            except ValueError:
                cursor.execute(query, (-1, f'%{search_text}%'))
                results = cursor.fetchall()

        # 清空建议列表
        self.suggestion_list.clear()

        # 如果有匹配结果，显示建议列表
        if results:
            self.suggestion_list.show()
            for user_id, username in results:
                item = QListWidgetItem(f"{username} (ID: {user_id})")
                item.setData(Qt.UserRole, user_id)  # 存储 user_id 在 item 中
                self.suggestion_list.addItem(item)
        else:
            self.suggestion_list.hide()
    
    #用户点击建议列表中的某一项    
    def on_suggestion_clicked(self, item):
        user_id = item.data(Qt.UserRole)  # 获取存储的 user_id
        self.search_input.clear()  # 清空搜索框
        self.suggestion_list.hide()  # 隐藏建议列表
        self.show_detail(user_id)  # 打开用户详情

    def refresh_users(self, page=1):
        # 确保 page 不小于 1
        page = max(1, page)
        self.current_page = page  # 保存当前页码
        # 彻底清理布局中的所有控件
        while self.user_layout.count() > 0:
            item = self.user_layout.takeAt(0)  # 移除布局中的第一个项
            widget = item.widget()
            if widget:
                widget.deleteLater()  # 异步删除控件
            del item  # 删除布局项

        # 添加加载中的提示
        loading = QLabel("加载中...")
        self.user_layout.addWidget(loading)

        # 异步加载用户数据
        self.loader = AsyncLoader('''
            SELECT id, username, balance FROM users 
            ORDER BY id LIMIT 10 OFFSET ?
        ''', ((page-1)*10,))
        self.loader.finished.connect(lambda data: self.update_users(page, data))
        self.loader.error.connect(lambda e: QMessageBox.critical(self, '错误', e))
        self.loader.start()

    def update_users(self, page, users):
        # 彻底清理布局中的所有控件（包括 "加载中..."）
        while self.user_layout.count() > 0:
            item = self.user_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
            del item

        # 添加用户条目
        for user_id, username, balance in users:
            item = QWidget()
            layout = QHBoxLayout()
            if username == 'hyyf':
                layout.addWidget(QLabel(f"{username} (ID: {user_id})"))
            else:
                layout.addWidget(QLabel(f"{username} (ID: {user_id})  余额: ¥{balance:.2f}"))
            btn = QPushButton("详情")
            btn.clicked.connect(lambda _, uid=user_id: self.show_detail(uid))
            layout.addWidget(btn)
            item.setLayout(layout)
            self.user_layout.addWidget(item)

        # 添加分页导航
        nav = QWidget()
        nav_layout = QHBoxLayout()

        # 上一页按钮
        btn_prev = QPushButton("上一页")
        btn_prev.setEnabled(page > 1)
        btn_prev.clicked.connect(lambda: self.refresh_users(page - 1))
        nav_layout.addWidget(btn_prev)

        # 添加伸缩空间，确保输入框居中
        nav_layout.addStretch()

        # 页码输入框和总页数标签的子布局（保持紧凑）
        page_layout = QHBoxLayout()
        page_input = QLineEdit()
        page_input.setText(str(page))  # 显示当前页码
        page_input.setFixedWidth(50)  # 设置输入框宽度
        page_input.setAlignment(Qt.AlignCenter)  # 居中对齐
        page_layout.addWidget(page_input)
        page_layout.addWidget(QLabel(f"/ {self.get_max_pages()} 页"))  # 显示总页数

        # 将页码子布局添加到主布局
        nav_layout.addLayout(page_layout)

        # 添加伸缩空间，确保输入框居中
        nav_layout.addStretch()

        # 下一页按钮
        btn_next = QPushButton("下一页")
        btn_next.clicked.connect(lambda: self.refresh_users(page + 1))
        nav_layout.addWidget(btn_next)

        # 将布局设置为导航控件
        nav.setLayout(nav_layout)
        self.user_layout.addWidget(nav)

        # 检查是否有下一页并动态启用/禁用下一页按钮
        self.count_loader = AsyncLoader("SELECT COUNT(*) FROM users")
        self.count_loader.finished.connect(
            lambda data: btn_next.setEnabled(page * 10 < data[0][0]))
        self.count_loader.start()

        # 连接页码输入框的回车事件
        page_input.returnPressed.connect(lambda: self.jump_to_page(page_input.text()))

    def get_max_pages(self):
        """计算最大页数"""
        with sqlite3.connect('shop_system.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
        return (total_users + 9) // 10  # 每页 10 个用户，向上取整

    def jump_to_page(self, input_text):
        """处理页码跳转"""
        try:
            target_page = int(input_text)
            max_pages = self.get_max_pages()
            
            if 1 <= target_page <= max_pages:
                self.refresh_users(target_page)
            else:
                QMessageBox.warning(self, "页码错误", "请输入正确的页码！")
        except ValueError:
            QMessageBox.warning(self, "页码错误", "请输入正确的页码！")

    def show_detail(self, user_id):
        self.detail_window = DetailWindow(user_id, self)
        # 连接子窗口的信号到主窗口的刷新方法
        self.detail_window.balance_updated.connect(lambda: self.refresh_users(self.current_page))
        self.detail_window.show()

    def add_user(self):
        dialog = AddUserDialog()
        if dialog.exec_():
            username = dialog.name_input.text().strip()
            if not username:
                QMessageBox.warning(self, "错误", "用户名不能为空")
                return
                
            with sqlite3.connect('shop_system.db') as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users WHERE username=?", (username,))
                if cursor.fetchone()[0] > 0:
                    QMessageBox.warning(self, "错误", "该用户名已存在，请使用其他用户名")
                    return
                    
                password_hash = hashlib.sha256("123456".encode()).hexdigest()
                try:
                    cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                                (username, password_hash))
                    conn.commit()
                    self.refresh_users()  # 刷新用户列表
                    #移除这条代码
                    #QMessageBox.information(self, "成功", "用户添加成功，默认密码为123456")
                except sqlite3.Error as e:
                    QMessageBox.critical(self, "错误", f"添加用户失败: {str(e)}")
    
    def import_from_excel(self):
        from PyQt5.QtWidgets import QFileDialog
        
        # 提示用户确认覆盖操作
        reply = QMessageBox.question(self, "确认覆盖", "导入将覆盖现有数据，是否继续？",
                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return
        
        # 选择 Excel 文件
        file_path, _ = QFileDialog.getOpenFileName(self, "选择Excel文件", "", "Excel Files (*.xlsx *.xls)")
        if not file_path:
            return

        try:
            # 读取 Excel 文件的所有工作表
            excel_file = pd.ExcelFile(file_path)
            imported_users = 0
            imported_transactions = 0
            skipped_hyyf = False  # 专门记录是否跳过了 hyyf
            invalid_usernames = []  # 记录无效用户名（空用户名）

            # 检查 Excel 文件中的重复用户名
            all_usernames = set()
            duplicate_usernames = set()
            for sheet_name in excel_file.sheet_names:
                df = pd.read_excel(file_path, sheet_name=sheet_name)
                columns = df.columns.tolist()

                if all(col in columns for col in ['username']) and len(columns) == 1:
                    for index, row in df.iterrows():
                        username = str(row['username']).strip()
                        if not username:  # 记录空用户名
                            invalid_usernames.append(f"工作表 '{sheet_name}' 第 {index+2} 行")
                            continue
                        if username in all_usernames:
                            duplicate_usernames.add(username)
                        else:
                            all_usernames.add(username)
                elif all(col in columns for col in ['时间', '类型', '金额', '类目']):
                    username = sheet_name
                    if not username:  # 工作表名为空（理论上不应该发生，但以防万一）
                        invalid_usernames.append(f"工作表 '{sheet_name}'")
                        continue
                    if username in all_usernames:
                        duplicate_usernames.add(username)
                    else:
                        all_usernames.add(username)

            # 如果有重复用户名，提示用户并停止导入
            if duplicate_usernames:
                QMessageBox.critical(self, "导入错误", 
                                    f"Excel 文件中存在重复的用户名：{', '.join(duplicate_usernames)}\n"
                                    "请确保所有用户名唯一后再导入！")
                return

            # 如果有空用户名，提示用户并停止导入
            if invalid_usernames:
                QMessageBox.critical(self, "导入错误", 
                                    f"Excel 文件中存在空用户名：\n" + "\n".join(invalid_usernames) + "\n"
                                    "请确保所有用户名不为空后再导入！")
                return

            # 检查是否包含管理员用户 hyyf
            if 'hyyf' in all_usernames:
                skipped_hyyf = True

            with sqlite3.connect('shop_system.db') as conn:
                cursor = conn.cursor()

                # 清空数据库
                cursor.execute("DELETE FROM transactions")
                cursor.execute("DELETE FROM users")

                # 重置 users 表的自增计数器
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")

                # 重新插入管理员用户
                admin_hash = hashlib.sha256("hyyf123".encode()).hexdigest()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, role, balance)
                    VALUES (?, ?, ?, ?)
                ''', ('hyyf', admin_hash, 'admin', 0.0))

                # 定义支持的格式
                user_only_format = ['username']
                full_transaction_format = ['时间', '类型', '金额', '类目']

                # 遍历所有工作表
                for sheet_name in excel_file.sheet_names:
                    df = pd.read_excel(file_path, sheet_name=sheet_name)
                    columns = df.columns.tolist()

                    # 检查格式 1：仅用户信息
                    if all(col in columns for col in user_only_format) and len(columns) == 1:
                        for index, row in df.iterrows():
                            username = str(row['username']).strip()
                            if username == 'hyyf':  # 跳过管理员用户
                                continue
                            
                            password_hash = hashlib.sha256("123456".encode()).hexdigest()
                            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                                        (username, password_hash))
                            imported_users += 1

                    # 检查格式 2：完整交易记录
                    elif all(col in columns for col in full_transaction_format):
                        username = sheet_name
                        if username == 'hyyf':  # 跳过管理员用户
                            continue

                        password_hash = hashlib.sha256("123456".encode()).hexdigest()
                        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                                    (username, password_hash))
                        user_id = cursor.lastrowid
                        imported_users += 1

                        for index, row in df.iterrows():
                            timestamp = row['时间']
                            trans_type = row['类型']
                            amount = float(row['金额'])
                            category = row['类目']

                            cursor.execute('''
                                INSERT INTO transactions (user_id, type, amount, category, timestamp)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (user_id, trans_type, amount, category, timestamp))
                            
                            if trans_type == 'topup':
                                cursor.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, user_id))
                            elif trans_type == 'consumption':
                                cursor.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, user_id))
                            
                            imported_transactions += 1

                    else:
                        QMessageBox.critical(self, "格式错误", 
                                        f"工作表 '{sheet_name}' 格式不正确。\n"
                                        "支持以下两种格式：\n"
                                        "1. 仅包含 'username' 列（导入用户）\n"
                                        "2. 包含 '时间', '类型', '金额', '类目' 列（与导出格式一致，导入交易记录）")
                        return

                conn.commit()

            self.refresh_users()
            # 改进提示信息
            if skipped_hyyf:
                QMessageBox.information(self, "导入完成", 
                                    f"成功导入 {imported_users} 个用户，{imported_transactions} 条交易记录，\n"
                                    f"跳过了管理员用户 'hyyf'")
            else:
                QMessageBox.information(self, "导入完成", 
                                    f"成功导入 {imported_users} 个用户，{imported_transactions} 条交易记录")

        except ValueError as ve:
            QMessageBox.critical(self, "数据错误", f"数据格式错误，请检查金额是否为数字: {str(ve)}")
        except sqlite3.IntegrityError as ie:
            QMessageBox.critical(self, "导入失败", f"数据库错误：{str(ie)}\n可能是用户名重复导致！")
        except Exception as e:
            QMessageBox.critical(self, "导入错误", f"导入失败: {str(e)}")

    def export_to_excel(self):
        def on_export_finished():
            QMessageBox.information(self, "完成", "导出成功")
            self.btn_export.setEnabled(True)  # 成功时启用按钮

        self.btn_export.setEnabled(False)
        self.export_thread = AsyncLoader("SELECT id, username FROM users")
        self.export_thread.finished.connect(
            lambda users: self._export_users(users, on_export_finished))
        self.export_thread.start()

    def _export_users(self, users, callback):
        try:
            # 确保 openpyxl 已安装
            try:
                from openpyxl import load_workbook
                from openpyxl.utils import get_column_letter
            except ImportError:
                QMessageBox.critical(self, "缺少依赖", "缺少 openpyxl 库，请安装：pip install openpyxl")
                self.btn_export.setEnabled(True)
                return

            # 写入 Excel 文件
            with sqlite3.connect('shop_system.db') as conn:
                with pd.ExcelWriter('交易记录.xlsx', engine='openpyxl') as writer:
                    for user_id, username in users:
                        for chunk in pd.read_sql(
                            f'''SELECT 
                                timestamp as 时间,
                                type as 类型,
                                amount as 金额,
                                category as 类目
                            FROM transactions 
                            WHERE user_id={user_id}
                            ORDER BY timestamp DESC''',
                            conn, chunksize=1000
                        ):
                            chunk.to_excel(writer, sheet_name=username[:30], index=False)

            # 打开 Excel 文件并调整列宽
            workbook = load_workbook('交易记录.xlsx')
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                for column in sheet.columns:
                    max_length = 0
                    column_letter = get_column_letter(column[0].column)
                    for cell in column:
                        try:
                            if cell.value:
                                cell_value = str(cell.value)
                                length = 0
                                for char in cell_value:
                                    if ord(char) > 127:
                                        length += 2
                                    else:
                                        length += 1
                                max_length = max(max_length, length)
                        except:
                            pass
                    adjusted_width = max_length + 2
                    sheet.column_dimensions[column_letter].width = adjusted_width

            workbook.save('交易记录.xlsx')
            callback()
        except PermissionError:
            QMessageBox.critical(self, "导出错误", "无法导出，请关闭原表格再导出Excel")
        except Exception as e:
            QMessageBox.critical(self, "导出错误", str(e))
        finally:
            self.btn_export.setEnabled(True)
    
    def calculate_revenue(self):
        with sqlite3.connect('shop_system.db') as conn:
            cursor = conn.cursor()
            
            # 计算所有用户的充值总额
            cursor.execute("""
                SELECT SUM(amount) 
                FROM transactions 
                WHERE type = 'topup'
            """)
            total_topup = cursor.fetchone()[0] or 0.0  # 如果没有记录，返回 0.0
            
            # 计算所有用户的消费总额
            cursor.execute("""
                SELECT SUM(amount) 
                FROM transactions 
                WHERE type = 'consumption'
            """)
            total_consumption = cursor.fetchone()[0] or 0.0  # 如果没有记录，返回 0.0
            
            # 计算所有用户的余额总和
            cursor.execute("SELECT COUNT(*) FROM users WHERE id != 1")  # 明确排除 id=1
            total_balance = cursor.fetchone()[0] or 0.0  # 如果没有记录，返回 0.0

            # 新增：统计用户数量
            cursor.execute("SELECT COUNT(*) FROM users WHERE id != 1")
            user_count = cursor.fetchone()[0] or 0  # 如果没有用户，返回 0

        return total_topup, total_consumption, total_balance,user_count
    
    def show_revenue(self):
        total_topup, total_consumption, total_balance,user_count = self.calculate_revenue()
        
        # 创建弹窗
        revenue_dialog = QMessageBox(self)
        revenue_dialog.setWindowTitle("营收情况")
        revenue_dialog.setText(
            f"用户数量：{user_count} 位\n"
            f"用户充值：{total_topup:.2f} 元\n"
            f"用户消费：{total_consumption:.2f} 元\n"
            f"余额：{total_balance:.2f} 元"
        )
        revenue_dialog.setStandardButtons(QMessageBox.Ok)
        revenue_dialog.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    init_db()  # 初始化数据库（仅在需要时创建表）
    login = LoginWindow()
    if login.exec_() == QDialog.Accepted:
        window = MainWindow()
        window.resize(1250, 1300)  # 设置初始大小
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)