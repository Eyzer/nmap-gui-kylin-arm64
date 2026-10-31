#include <QApplication>
#include <QMainWindow>
#include <QRegExp>
#include <QTextCursor>
#include <QFile>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGridLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QTabWidget>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QSplitter>
#include <QProcess>
#include <QProcessEnvironment>
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QDir>
#include <QTime>
#include <QGroupBox>
#include <QApplication>
#include <QClipboard>
#include <unistd.h>

static QString T(const char *s) { return QString::fromUtf8(s); }

class MainWin : public QMainWindow {
    Q_OBJECT
public:
    MainWin() {
        setWindowTitle(T("Nmap 图形界面 - 网络扫描工具"));
        resize(1080, 720);
        buildUi();
        refreshPreview();
    }

private:
    QLineEdit *m_target;
    QComboBox *m_scanType, *m_ports, *m_timing;
    QCheckBox *m_sV, *m_os, *m_aggr, *m_pn, *m_noDns, *m_open, *m_verbose, *m_reason;
    QCheckBox *m_catDefault, *m_catVuln, *m_catDiscovery, *m_catSafe, *m_catAuth;
    QLineEdit *m_scriptName, *m_scriptArgs, *m_extra;
    QPlainTextEdit *m_out;
    QTableWidget *m_table;
    QLabel *m_cmdLabel, *m_status;
    QPushButton *m_btnStart, *m_btnStop, *m_btnSave, *m_btnClear;
    QProcess *m_proc;
    QTabWidget *m_resultTabs;
    bool m_running;

    static bool isRoot() { return geteuid() == 0; }

    QString nmapBin() const {
        QString p = T("/opt/nmapgui/bin/nmap");
        if (QFileInfo::exists(p)) return p;
        return T("nmap");
    }
    QString dataDir() const {
        QString d = T("/opt/nmapgui/share/nmap");
        if (QDir(d).exists()) return d;
        return QString();
    }

    void buildUi() {
        QWidget *central = new QWidget(this);
        QVBoxLayout *root = new QVBoxLayout(central);
        root->setContentsMargins(10, 10, 10, 8);
        root->setSpacing(8);

        // ---- 目标行 ----
        QHBoxLayout *hl = new QHBoxLayout();
        QLabel *lb = new QLabel(T("扫描目标:"), central);
        lb->setMinimumWidth(70);
        m_target = new QLineEdit(central);
        m_target->setPlaceholderText(T("IP / 域名 / 网段，例如 192.168.1.0/24，多个用空格分隔"));
        m_target->setText(T("127.0.0.1"));
        QPushButton *bLocal = new QPushButton(T("本机"), central);
        QPushButton *bLan = new QPushButton(T("局域网"), central);
        hl->addWidget(lb);
        hl->addWidget(m_target, 1);
        hl->addWidget(bLocal);
        hl->addWidget(bLan);
        root->addLayout(hl);

        connect(bLocal, &QPushButton::clicked, this, [this] { m_target->setText(T("127.0.0.1")); refreshPreview(); });
        connect(bLan, &QPushButton::clicked, this, [this] { m_target->setText(T("192.168.1.0/24")); refreshPreview(); });

        // ---- 参数页签 ----
        QTabWidget *ptabs = new QTabWidget(central);
        ptabs->addTab(buildScanTab(), T("扫描设置"));
        ptabs->addTab(buildScriptTab(), T("NSE 脚本与高级"));
        root->addWidget(ptabs, 0);

        // ---- 结果区 ----
        m_resultTabs = new QTabWidget(central);
        m_out = new QPlainTextEdit(central);
        m_out->setReadOnly(true);
        m_out->setStyleSheet(T("QPlainTextEdit{font-family:monospace;font-size:12px;background:#111418;color:#d8e0e8;}"));
        m_table = new QTableWidget(0, 5, central);
        m_table->setHorizontalHeaderLabels(QStringList() << T("端口") << T("协议") << T("状态") << T("服务") << T("版本"));
        m_table->horizontalHeader()->setStretchLastSection(true);
        m_table->verticalHeader()->setVisible(false);
        m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_resultTabs->addTab(m_out, T("实时输出"));
        m_resultTabs->addTab(m_table, T("端口结果"));
        root->addWidget(m_resultTabs, 1);

        // ---- 命令预览 ----
        m_cmdLabel = new QLabel(central);
        m_cmdLabel->setWordWrap(true);
        m_cmdLabel->setStyleSheet(T("QLabel{color:#2F6FE4;font-family:monospace;padding:4px;background:#1b1f24;border-radius:4px;}"));
        root->addWidget(m_cmdLabel);

        // ---- 按钮行 ----
        QHBoxLayout *bl = new QHBoxLayout();
        m_btnStart = new QPushButton(T("开始扫描"), central);
        m_btnStart->setMinimumHeight(34);
        m_btnStart->setStyleSheet(T("QPushButton{background:#2F6FE4;color:#fff;border:none;border-radius:5px;padding:6px 22px;font-weight:bold;}QPushButton:disabled{background:#4a5568;color:#9aa5b1;}"));
        m_btnStop = new QPushButton(T("停止"), central);
        m_btnStop->setEnabled(false);
        m_btnStop->setMinimumHeight(34);
        m_btnSave = new QPushButton(T("保存结果"), central);
        m_btnSave->setMinimumHeight(34);
        m_btnClear = new QPushButton(T("清空"), central);
        m_btnClear->setMinimumHeight(34);
        m_status = new QLabel(isRoot() ? T("就绪（已具备完整扫描权限）") : T("就绪（普通用户，SYN/OS 扫描需提权）"), central);
        m_status->setStyleSheet(T("QLabel{color:#8b98a5;}"));
        bl->addWidget(m_btnStart);
        bl->addWidget(m_btnStop);
        bl->addWidget(m_btnSave);
        bl->addWidget(m_btnClear);
        bl->addSpacing(12);
        bl->addWidget(m_status, 1);
        root->addLayout(bl);

        QLabel *foot = new QLabel(T("Nmap 图形界面 · 基于 Nmap 官方扫描引擎 · 二次开发封装  ·  仅供合法授权的网络检测使用"), central);
        foot->setAlignment(Qt::AlignCenter);
        foot->setStyleSheet(T("QLabel{color:#6b7684;font-size:11px;padding-top:2px;}"));
        root->addWidget(foot);

        setCentralWidget(central);

        connect(m_btnStart, &QPushButton::clicked, this, &MainWin::startScan);
        connect(m_btnStop, &QPushButton::clicked, this, &MainWin::stopScan);
        connect(m_btnSave, &QPushButton::clicked, this, &MainWin::saveResult);
        connect(m_btnClear, &QPushButton::clicked, this, [this] {
            m_out->clear();
            m_table->setRowCount(0);
            m_status->setText(T("已清空"));
        });
        connect(m_target, &QLineEdit::textChanged, this, &MainWin::refreshPreview);

        m_proc = new QProcess(this);
        m_proc->setProcessChannelMode(QProcess::MergedChannels);
        connect(m_proc, &QProcess::readyReadStandardOutput, this, &MainWin::onRead);
        connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &MainWin::onFinish);
        connect(m_proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
            if (e == QProcess::FailedToStart) {
                m_out->appendPlainText(T("[错误] 无法启动 nmap，请确认程序完整。"));
                m_running = false;
                m_btnStart->setEnabled(true);
                m_btnStop->setEnabled(false);
            }
        });
        m_running = false;
    }

    QWidget *buildScanTab() {
        QWidget *w = new QWidget(this);
        QGridLayout *g = new QGridLayout(w);
        g->setContentsMargins(14, 14, 14, 14);
        g->setHorizontalSpacing(14);
        g->setVerticalSpacing(10);

        g->addWidget(new QLabel(T("扫描类型:")), 0, 0);
        m_scanType = new QComboBox(w);
        m_scanType->addItem(T("TCP 连接扫描 (-sT，无需特权，稳定)"), T("-sT"));
        m_scanType->addItem(T("SYN 半开扫描 (-sS，需管理员权限，快速隐蔽)"), T("-sS"));
        m_scanType->addItem(T("UDP 扫描 (-sU，需管理员权限，较慢)"), T("-sU"));
        m_scanType->addItem(T("主机发现 (-sn，只探测存活，不扫端口)"), T("-sn"));
        m_scanType->addItem(T("ACK 扫描 (-sA，探测防火墙规则)"), T("-sA"));
        m_scanType->addItem(T("FIN 扫描 (-sF，绕过简单过滤)"), T("-sF"));
        g->addWidget(m_scanType, 0, 1, 1, 3);

        g->addWidget(new QLabel(T("端口范围:")), 1, 0);
        m_ports = new QComboBox(w);
        m_ports->setEditable(true);
        m_ports->addItem(T("常用 100 个端口 (--top-ports 100)"), T("--top-ports 100"));
        m_ports->addItem(T("前 1000 个端口 (默认)"), T(""));
        m_ports->addItem(T("全部 65535 端口 (-p-)"), T("-p-"));
        m_ports->addItem(T("指定端口 (-p 80,443)"), T("-p 80,443"));
        g->addWidget(m_ports, 1, 1, 1, 3);

        g->addWidget(new QLabel(T("扫描速度:")), 2, 0);
        m_timing = new QComboBox(w);
        m_timing->addItem(T("T4 较快（推荐，内网稳定）"), T("-T4"));
        m_timing->addItem(T("T3 常规（默认）"), T("-T3"));
        m_timing->addItem(T("T2 较慢（避免丢包）"), T("-T2"));
        m_timing->addItem(T("T1 隐蔽（很慢）"), T("-T1"));
        m_timing->addItem(T("T5 极速（可能丢包）"), T("-T5"));
        g->addWidget(m_timing, 2, 1, 1, 3);

        QGroupBox *gb = new QGroupBox(T("探测选项"), w);
        QGridLayout *gg = new QGridLayout(gb);
        m_sV = new QCheckBox(T("识别服务与版本 (-sV)"), gb);
        m_os = new QCheckBox(T("识别操作系统 (-O，需管理员权限)"), gb);
        m_aggr = new QCheckBox(T("全面扫描 (-A，含版本/系统/脚本)"), gb);
        m_pn = new QCheckBox(T("跳过主机发现 (-Pn)"), gb);
        m_noDns = new QCheckBox(T("不做域名解析 (-n，更快)"), gb);
        m_open = new QCheckBox(T("只显示开放端口 (--open)"), gb);
        m_verbose = new QCheckBox(T("详细输出 (-v)"), gb);
        m_reason = new QCheckBox(T("显示端口状态原因 (--reason)"), gb);
        m_sV->setChecked(true);
        m_open->setChecked(true);
        m_pn->setChecked(false);
        gg->addWidget(m_sV, 0, 0);
        gg->addWidget(m_os, 0, 1);
        gg->addWidget(m_aggr, 1, 0);
        gg->addWidget(m_pn, 1, 1);
        gg->addWidget(m_noDns, 2, 0);
        gg->addWidget(m_open, 2, 1);
        gg->addWidget(m_verbose, 3, 0);
        gg->addWidget(m_reason, 3, 1);
        g->addWidget(gb, 3, 0, 1, 4);

        QLabel *hint = new QLabel(T("提示：SYN、UDP、OS 识别需要管理员权限，启动时会自动请求授权。"), w);
        hint->setStyleSheet(T("QLabel{color:#8b98a5;font-size:11px;}"));
        g->addWidget(hint, 4, 0, 1, 4);

        const QList<QComboBox *> cbs = {m_scanType, m_ports, m_timing};
        for (QComboBox *c : cbs) connect(c, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWin::refreshPreview);
        connect(m_ports->lineEdit(), &QLineEdit::textChanged, this, &MainWin::refreshPreview);
        QList<QCheckBox *> cks = {m_sV, m_os, m_aggr, m_pn, m_noDns, m_open, m_verbose, m_reason};
        for (QCheckBox *c : cks) connect(c, &QCheckBox::stateChanged, this, &MainWin::refreshPreview);
        return w;
    }

    QWidget *buildScriptTab() {
        QWidget *w = new QWidget(this);
        QVBoxLayout *v = new QVBoxLayout(w);
        v->setContentsMargins(14, 14, 14, 14);
        v->setSpacing(10);

        QGroupBox *gb = new QGroupBox(T("脚本类别 (--script)"), w);
        QGridLayout *gg = new QGridLayout(gb);
        m_catDefault = new QCheckBox(T("default 默认脚本集"), gb);
        m_catVuln = new QCheckBox(T("vuln 漏洞检测"), gb);
        m_catDiscovery = new QCheckBox(T("discovery 信息发现"), gb);
        m_catSafe = new QCheckBox(T("safe 安全脚本"), gb);
        m_catAuth = new QCheckBox(T("auth 弱口令检测"), gb);
        m_catDefault->setChecked(false);
        gg->addWidget(m_catDefault, 0, 0);
        gg->addWidget(m_catVuln, 0, 1);
        gg->addWidget(m_catDiscovery, 1, 0);
        gg->addWidget(m_catSafe, 1, 1);
        gg->addWidget(m_catAuth, 2, 0);
        v->addWidget(gb);

        QFormLayout *f = new QFormLayout();
        m_scriptName = new QLineEdit(w);
        m_scriptName->setPlaceholderText(T("例如 http-title,ssh-brute（留空则按类别执行）"));
        m_scriptArgs = new QLineEdit(w);
        m_scriptArgs->setPlaceholderText(T("例如 user=admin,pass=123456"));
        f->addRow(T("指定脚本:"), m_scriptName);
        f->addRow(T("脚本参数:"), m_scriptArgs);
        v->addLayout(f);

        QGroupBox *gb2 = new QGroupBox(T("附加参数"), w);
        QVBoxLayout *v2 = new QVBoxLayout(gb2);
        m_extra = new QLineEdit(gb2);
        m_extra->setPlaceholderText(T("直接追加到命令行，例如 --max-retries 2 --host-timeout 60s"));
        v2->addWidget(m_extra);
        v->addWidget(gb2);
        v->addStretch(1);

        QList<QCheckBox *> cks = {m_catDefault, m_catVuln, m_catDiscovery, m_catSafe, m_catAuth};
        for (QCheckBox *c : cks) connect(c, &QCheckBox::stateChanged, this, &MainWin::refreshPreview);
        connect(m_scriptName, &QLineEdit::textChanged, this, &MainWin::refreshPreview);
        connect(m_scriptArgs, &QLineEdit::textChanged, this, &MainWin::refreshPreview);
        connect(m_extra, &QLineEdit::textChanged, this, &MainWin::refreshPreview);
        return w;
    }

    QStringList buildArgs(bool &needRoot) {
        QStringList a;
        QString st = m_scanType->currentData().toString();
        if (st == T("-sS") || st == T("-sU") || st == T("-sA") || st == T("-sF")) needRoot = true;
        if (m_os->isChecked()) needRoot = true;
        if (m_aggr->isChecked()) needRoot = true;

        QString dd = dataDir();
        if (!dd.isEmpty()) { a << T("--datadir") << dd; }
        a << st;

        QString shown = m_ports->currentIndex() >= 0 ? m_ports->itemText(m_ports->currentIndex()) : QString();
        QString pv = m_ports->currentText().trimmed();
        if (pv == shown) pv = m_ports->currentData().toString();
        if (!pv.isEmpty()) {
            if (!pv.startsWith(T("-"))) pv = T("-p ") + pv;
            a << pv.split(' ', QString::SkipEmptyParts);
        }

        if (m_sV->isChecked()) a << T("-sV");
        if (m_os->isChecked()) a << T("-O");
        if (m_aggr->isChecked()) a << T("-A");
        if (m_pn->isChecked()) a << T("-Pn");
        if (m_noDns->isChecked()) a << T("-n");
        if (m_open->isChecked()) a << T("--open");
        if (m_verbose->isChecked()) a << T("-v");
        if (m_reason->isChecked()) a << T("--reason");
        a << m_timing->currentData().toString();

        QStringList cats;
        if (m_catDefault->isChecked()) cats << T("default");
        if (m_catVuln->isChecked()) cats << T("vuln");
        if (m_catDiscovery->isChecked()) cats << T("discovery");
        if (m_catSafe->isChecked()) cats << T("safe");
        if (m_catAuth->isChecked()) cats << T("auth");
        QString sn = m_scriptName->text().trimmed();
        QString scriptExpr;
        if (!sn.isEmpty()) scriptExpr = sn;
        else if (!cats.isEmpty()) scriptExpr = cats.join(',');
        if (!scriptExpr.isEmpty()) {
            QString sa = m_scriptArgs->text().trimmed();
            if (!sa.isEmpty()) scriptExpr += " --script-args " + sa;
            a << T("--script") << scriptExpr;
        }

        QString ex = m_extra->text().trimmed();
        if (!ex.isEmpty()) a << ex.split(' ', QString::SkipEmptyParts);

        QString tgt = m_target->text().trimmed();
        if (!tgt.isEmpty()) a << tgt.split(' ', QString::SkipEmptyParts);
        return a;
    }

    void refreshPreview() {
        if (!m_target) return;
        bool needRoot = false;
        QStringList a = buildArgs(needRoot);
        QStringList pretty;
        for (const QString &s : a) pretty << (s.contains(' ') ? "\"" + s + "\"" : s);
        QString prefix = needRoot && !isRoot() ? T("pkexec ") : QString();
        m_cmdLabel->setText(prefix + nmapBin() + " " + pretty.join(' '));
    }

    void startScan() {
        if (m_running) return;
        QString tgt = m_target->text().trimmed();
        if (tgt.isEmpty()) {
            QMessageBox::warning(this, T("提示"), T("请先填写扫描目标。"));
            return;
        }
        bool needRoot = false;
        QStringList args = buildArgs(needRoot);

        QString prog;
        if (needRoot && !isRoot()) {
            prog = T("pkexec");
            if (!QFileInfo::exists(T("/usr/bin/pkexec"))) {
                QMessageBox::warning(this, T("权限不足"),
                    T("SYN/UDP/系统识别扫描需要管理员权限，未找到授权组件。\n请改用「TCP 连接扫描 (-sT)」。"));
                return;
            }
            args.prepend(nmapBin());
        } else {
            prog = nmapBin();
        }

        m_out->clear();
        m_table->setRowCount(0);
        m_resultTabs->setCurrentIndex(0);
        m_out->appendPlainText(T("== 开始扫描 =="));
        m_out->appendPlainText(prog + " " + args.join(' '));
        m_out->appendPlainText(QString());
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert(T("LD_LIBRARY_PATH"), T("/opt/nmapgui/lib"));
        m_proc->setProcessEnvironment(env);
        m_proc->setProgram(prog);
        m_proc->setArguments(args);
        m_proc->start();
        m_running = true;
        m_btnStart->setEnabled(false);
        m_btnStop->setEnabled(true);
        m_status->setText(T("扫描中..."));
    }

    void stopScan() {
        if (!m_running) return;
        m_proc->kill();
        m_out->appendPlainText(T("\n[已手动停止]"));
        m_status->setText(T("已停止"));
    }

    void onRead() {
        QByteArray d = m_proc->readAllStandardOutput();
        QString s = QString::fromUtf8(d);
        m_out->insertPlainText(s);
        m_out->moveCursor(QTextCursor::End);
        parseLines(s);
    }

    void parseLines(const QString &s) {
        static QRegExp re(T("^(\\d+)/(tcp|udp)\\s+(open|open\\|filtered|closed|filtered)\\s+(\\S+)\\s*(.*)$"));
        static QString buf;
        buf += s;
        int idx;
        while ((idx = buf.indexOf('\n')) >= 0) {
            QString line = buf.left(idx);
            buf = buf.mid(idx + 1);
            if (re.indexIn(line) == 0) {
                int r = m_table->rowCount();
                m_table->insertRow(r);
                m_table->setItem(r, 0, new QTableWidgetItem(re.cap(1)));
                m_table->setItem(r, 1, new QTableWidgetItem(re.cap(2)));
                m_table->setItem(r, 2, new QTableWidgetItem(re.cap(3)));
                m_table->setItem(r, 3, new QTableWidgetItem(re.cap(4)));
                m_table->setItem(r, 4, new QTableWidgetItem(re.cap(5).trimmed()));
            }
        }
    }

    void onFinish(int code, QProcess::ExitStatus) {
        m_running = false;
        m_btnStart->setEnabled(true);
        m_btnStop->setEnabled(false);
        m_out->appendPlainText(T("\n== 扫描结束 (退出码 ") + QString::number(code) + T(") =="));
        if (m_table->rowCount() > 0) {
            m_status->setText(T("扫描完成，发现 ") + QString::number(m_table->rowCount()) + T(" 个端口记录"));
            m_resultTabs->setCurrentIndex(1);
        } else {
            m_status->setText(T("扫描完成"));
        }
    }

    void saveResult() {
        QString fn = QFileDialog::getSaveFileName(this, T("保存扫描结果"),
                        QDir::homePath() + T("/nmap_scan_") + QTime::currentTime().toString("hhmmss") + T(".txt"),
                        T("文本文件 (*.txt);;所有文件 (*)"));
        if (fn.isEmpty()) return;
        QFile f(fn);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, T("失败"), T("无法写入文件。"));
            return;
        }
        f.write(m_cmdLabel->text().toUtf8());
        f.write("\n\n");
        f.write(m_out->toPlainText().toUtf8());
        f.close();
        m_status->setText(T("已保存: ") + fn);
    }
};

#include "main.moc"

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    app.setApplicationName(T("Nmap 图形界面"));
    MainWin w;
    w.show();
    return app.exec();
}
