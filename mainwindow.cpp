#include "mainwindow.h"

// Qt layout headers
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QPalette>
#include <QFont>
#include <QRandomGenerator>

// Standard library header needed for std::remove
#include <algorithm>

// Constructor: called when we create the MainWindow object
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      terminalView(nullptr),
      listView(nullptr),
      listTitleLabel(nullptr),
      startScanButton(nullptr),
      viewBlacklistButton(nullptr),
      networkGraphButton(nullptr),
      alertsButton(nullptr),
      simulateTrafficButton(nullptr),
      blockIpButton(nullptr),
      undoBlockButton(nullptr),
      scanTimer(new QTimer(this)),
      scanning(false)
{
    // Build the graphical user interface
    setupUi();

    // Apply dark theme and neon green text
    setupStyles();

    // Initialize our data structures with default values
    setupDataStructures();

    // Connect the timer to the slot that processes one packet
    connect(scanTimer, &QTimer::timeout, this, &MainWindow::onProcessNextPacket);

    // Set how often we want to process packets (e.g., every 500 milliseconds)
    scanTimer->setInterval(500);
}

// Destructor: nothing special needed because Qt and STL will clean up automatically
MainWindow::~MainWindow()
{
}

// --------------------------------------------------
// UI Setup
// --------------------------------------------------
void MainWindow::setupUi()
{
    // Create a central widget to hold everything
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    // Main horizontal layout: sidebar on the left, content on the right
    QHBoxLayout *mainLayout = new QHBoxLayout(central);

    // -------------------------
    // Sidebar (left)
    // -------------------------
    QVBoxLayout *sidebarLayout = new QVBoxLayout();

    // Create sidebar buttons
    startScanButton = new QPushButton("Start Scan");
    viewBlacklistButton = new QPushButton("View Blacklist");
    networkGraphButton = new QPushButton("Network Graph");
    alertsButton = new QPushButton("Alerts");

    // Add buttons to sidebar layout
    sidebarLayout->addWidget(startScanButton);
    sidebarLayout->addWidget(viewBlacklistButton);
    sidebarLayout->addWidget(networkGraphButton);
    sidebarLayout->addWidget(alertsButton);

    // Add some stretch at the bottom to push buttons to the top
    sidebarLayout->addStretch();

    // Connect sidebar buttons to their slots
    connect(startScanButton, &QPushButton::clicked, this, &MainWindow::onStartScanClicked);
    connect(viewBlacklistButton, &QPushButton::clicked, this, &MainWindow::onViewBlacklistClicked);
    connect(networkGraphButton, &QPushButton::clicked, this, &MainWindow::onNetworkGraphClicked);
    connect(alertsButton, &QPushButton::clicked, this, &MainWindow::onAlertsClicked);

    // -------------------------
    // Right side: list view + controls + terminal
    // -------------------------
    QVBoxLayout *rightLayout = new QVBoxLayout();

    // Label above the list to show what we are looking at
    listTitleLabel = new QLabel("Network Graph");
    rightLayout->addWidget(listTitleLabel);

    // List widget to show blacklist, graph, or alerts
    listView = new QListWidget();
    rightLayout->addWidget(listView, 2); // Give it more vertical space

    // Buttons row for Simulate Traffic, Block IP, Undo Block
    QHBoxLayout *controlLayout = new QHBoxLayout();
    simulateTrafficButton = new QPushButton("Simulate Traffic");
    blockIpButton = new QPushButton("Block IP");
    undoBlockButton = new QPushButton("Undo Block");

    controlLayout->addWidget(simulateTrafficButton);
    controlLayout->addWidget(blockIpButton);
    controlLayout->addWidget(undoBlockButton);
    controlLayout->addStretch();

    // Add control buttons row to the right layout
    rightLayout->addLayout(controlLayout);

    // Connect control buttons to their slots
    connect(simulateTrafficButton, &QPushButton::clicked, this, &MainWindow::onSimulateTrafficClicked);
    connect(blockIpButton, &QPushButton::clicked, this, &MainWindow::onBlockIpClicked);
    connect(undoBlockButton, &QPushButton::clicked, this, &MainWindow::onUndoBlockClicked);

    // Terminal-like text area at the bottom
    terminalView = new QTextEdit();
    terminalView->setReadOnly(true); // We do not want the user to edit it

    // Add the terminal to the right layout
    rightLayout->addWidget(terminalView, 1); // Give it some vertical space

    // -------------------------
    // Put sidebar and right side into the main layout
    // -------------------------
    mainLayout->addLayout(sidebarLayout, 1); // Sidebar takes less width
    mainLayout->addLayout(rightLayout, 3);   // Right side takes more width

    // Set the window title
    setWindowTitle("Intrusion Detection & Management System (IDS)");
}

// Apply dark background and neon green text
void MainWindow::setupStyles()
{
    // Set a dark background for the whole window
    QPalette palette;
    palette.setColor(QPalette::Window, QColor("#000000"));
    palette.setColor(QPalette::WindowText, QColor("#39FF14"));
    palette.setColor(QPalette::Base, QColor("#000000"));
    palette.setColor(QPalette::Text, QColor("#39FF14"));
    palette.setColor(QPalette::Button, QColor("#000000"));
    palette.setColor(QPalette::ButtonText, QColor("#39FF14"));
    palette.setColor(QPalette::Highlight, QColor("#39FF14"));
    palette.setColor(QPalette::HighlightedText, QColor("#000000"));
    setPalette(palette);

    // Apply a simple stylesheet to buttons and list/terminal for consistent neon look
    QString commonStyle =
        "QWidget { background-color: #000000; color: #39FF14; }"
        "QPushButton { border: 1px solid #39FF14; padding: 5px; }"
        "QPushButton:hover { background-color: #003300; }"
        "QListWidget { border: 1px solid #39FF14; }"
        "QTextEdit { border: 1px solid #39FF14; }";

    this->setStyleSheet(commonStyle);

    // Set a monospace font for the terminal for a "hacker" look
    QFont terminalFont("Consolas");
    terminalFont.setPointSize(10);
    terminalView->setFont(terminalFont);
}

// --------------------------------------------------
// Data Structures Initialization
// --------------------------------------------------
void MainWindow::setupDataStructures()
{
    // Protected ports in a std::set (BST)
    protectedPorts.insert(21);  // FTP
    protectedPorts.insert(22);  // SSH
    protectedPorts.insert(80);  // HTTP
    protectedPorts.insert(443); // HTTPS

    // Blacklist starts empty (unordered_set)
    blacklist.clear();

    // Network graph starts empty (map<string, vector<string>>)
    networkGraph.clear();

    // Alerts priority queue starts empty
    while (!alertQueue.empty())
    {
        alertQueue.pop();
    }

    // Stack for undo blocked IPs starts empty
    while (!undoBlockedIps.empty())
    {
        undoBlockedIps.pop();
    }

    // Insert some bad words into the Trie
    badWordTrie.insert("ATTACK");
    badWordTrie.insert("VIRUS");
    badWordTrie.insert("MALWARE");
    badWordTrie.insert("HACK");
}

// --------------------------------------------------
// Sidebar Slots
// --------------------------------------------------

// Called when "Start Scan" is clicked
void MainWindow::onStartScanClicked()
{
    if (!scanning)
    {
        // If not already scanning, start the timer
        scanning = true;
        scanTimer->start();
        logToTerminal(">> Scan started...");
        startScanButton->setText("Stop Scan");
    }
    else
    {
        // If already scanning, stop the timer
        scanning = false;
        scanTimer->stop();
        logToTerminal(">> Scan stopped.");
        startScanButton->setText("Start Scan");
    }
}

// Show the blacklist in the list view
void MainWindow::onViewBlacklistClicked()
{
    listTitleLabel->setText("Blacklisted IPs");
    refreshBlacklistView();
}

// Show the network graph in the list view
void MainWindow::onNetworkGraphClicked()
{
    listTitleLabel->setText("Network Graph");
    refreshNetworkGraphView();
}

// Show alerts in the list view
void MainWindow::onAlertsClicked()
{
    listTitleLabel->setText("Alerts (Critical -> Low)");
    refreshAlertsView();
}

// --------------------------------------------------
// Control Buttons Slots
// --------------------------------------------------

// Simulate random network traffic and enqueue packets
void MainWindow::onSimulateTrafficClicked()
{
    // Generate a small batch of packets
    const int packetCount = 10;
    for (int i = 0; i < packetCount; ++i)
    {
        Packet p = generateRandomPacket();
        enqueuePacket(p);
    }

    logToTerminal(">> Simulated traffic: 10 packets added to queue.");

    // If scanning is not started, we can still process manually by calling onProcessNextPacket()
    // But here we rely on Start Scan's timer to process them if enabled.
}

// Block an IP (moves it from the graph into the blacklist)
void MainWindow::onBlockIpClicked()
{
    // Choose an IP from the network graph
    string ip = chooseIpToBlock();
    if (ip.empty())
    {
        logToTerminal(">> No IP available in network graph to block.");
        return;
    }

    // Insert IP into blacklist
    blacklist.insert(ip);

    // Push to undo stack so we can undo this action
    undoBlockedIps.push(ip);

    // Remove this IP from the network graph as a source
    networkGraph.erase(ip);

    // Also remove this IP as a destination from all adjacency lists
    for (auto &entry : networkGraph)
    {
        vector<string> &destinations = entry.second;
        destinations.erase(
            remove(destinations.begin(), destinations.end(), ip),
            destinations.end());
    }

    QString msg = ">> Blocked IP: " + QString::fromStdString(ip);
    logToTerminal(msg);

    // Refresh blacklist view if it is currently shown
    if (listTitleLabel->text().contains("Blacklisted", Qt::CaseInsensitive))
    {
        refreshBlacklistView();
    }
}

// Undo the last blocked IP using the stack
void MainWindow::onUndoBlockClicked()
{
    if (undoBlockedIps.empty())
    {
        logToTerminal(">> Nothing to undo.");
        return;
    }

    // Get the last blocked IP
    string ip = undoBlockedIps.top();
    undoBlockedIps.pop();

    // Remove it from the blacklist
    auto it = blacklist.find(ip);
    if (it != blacklist.end())
    {
        blacklist.erase(it);
    }

    QString msg = ">> Undo block: " + QString::fromStdString(ip) + " removed from blacklist.";
    logToTerminal(msg);

    // Refresh blacklist view if currently visible
    if (listTitleLabel->text().contains("Blacklisted", Qt::CaseInsensitive))
    {
        refreshBlacklistView();
    }
}

// --------------------------------------------------
// Timer Slot - Process Next Packet From Queue
// --------------------------------------------------
void MainWindow::onProcessNextPacket()
{
    // If there is no packet in the queue, just log and return
    if (packetQueue.empty())
    {
        logToTerminal(">> No packets to scan...");
        return;
    }

    // Get the next packet from the front of the queue
    Packet p = packetQueue.front();
    packetQueue.pop();

    // Log that we are scanning this packet
    QString info = QString("Scanning packet... %1 -> %2 on port %3")
                       .arg(QString::fromStdString(p.sourceIp))
                       .arg(QString::fromStdString(p.destinationIp))
                       .arg(p.port);
    logToTerminal(info);

    // Scan the packet for suspicious activity
    scanPacket(p);

    // After scanning, we refresh views to show new graph/blacklist/alerts
    if (listTitleLabel->text().contains("Network", Qt::CaseInsensitive))
    {
        refreshNetworkGraphView();
    }
    else if (listTitleLabel->text().contains("Blacklisted", Qt::CaseInsensitive))
    {
        refreshBlacklistView();
    }
    else if (listTitleLabel->text().contains("Alerts", Qt::CaseInsensitive))
    {
        refreshAlertsView();
    }
}

// --------------------------------------------------
// Packet Generation and Scanning
// --------------------------------------------------

// Generate a random IP address in a simple private range
static string randomIp()
{
    // Using C++ random from <QRandomGenerator> for convenience
    int a = 192;
    int b = 168;
    int c = QRandomGenerator::global()->bounded(0, 256);
    int d = QRandomGenerator::global()->bounded(1, 255);

    return to_string(a) + "." + to_string(b) + "." + to_string(c) + "." + to_string(d);
}

// Generate a random packet with random IPs, port, and data
Packet MainWindow::generateRandomPacket()
{
    Packet p;

    // Random source and destination IP
    p.sourceIp = randomIp();
    p.destinationIp = randomIp();

    // Random port (include some protected ones)
    int possiblePorts[] = {21, 22, 80, 443, 8080, 3306, 53};
    int index = QRandomGenerator::global()->bounded(0, 7);
    p.port = possiblePorts[index];

    // Random data: sometimes include bad words
    int r = QRandomGenerator::global()->bounded(0, 4);
    if (r == 0)
        p.data = "Normal HTTP request";
    else if (r == 1)
        p.data = "User login data";
    else if (r == 2)
        p.data = "ATTACK detected in payload";
    else
        p.data = "Possible VIRUS signature found";

    return p;
}

// Put a packet into the packet queue
void MainWindow::enqueuePacket(const Packet &packet)
{
    packetQueue.push(packet);
}

// Scan a packet and update data structures / generate alerts
void MainWindow::scanPacket(const Packet &packet)
{
    // 1. Update network graph: source -> destination
    networkGraph[packet.sourceIp].push_back(packet.destinationIp);

    // 2. Check if source IP is already in blacklist
    bool isBlacklisted = (blacklist.find(packet.sourceIp) != blacklist.end());

    // 3. Check if destination port is protected
    bool isProtectedPort = (protectedPorts.find(packet.port) != protectedPorts.end());

    // 4. Check for bad words in packet data using Trie
    bool hasBadWord = badWordTrie.containsBadWord(packet.data);

    // Determine severity and message
    int severity = 0;
    string message;

    if (isBlacklisted)
    {
        severity = 4;
        message = "Blacklisted IP attempted connection: " + packet.sourceIp;
    }
    else if (hasBadWord && isProtectedPort)
    {
        severity = 4;
        message = "Critical: Suspicious payload on protected port " + to_string(packet.port);
    }
    else if (hasBadWord)
    {
        severity = 3;
        message = "High: Suspicious payload from " + packet.sourceIp;
    }
    else if (isProtectedPort)
    {
        severity = 2;
        message = "Medium: Access to protected port " + to_string(packet.port);
    }
    else
    {
        severity = 1;
        message = "Low: Normal traffic " + packet.sourceIp + " -> " + packet.destinationIp;
    }

    // Create an alert and push it into priority queue
    Alert alert;
    alert.message = message;
    alert.severity = severity;
    alert.sourceIp = packet.sourceIp;

    alertQueue.push(alert);

    // Log alert to terminal
    QString qMessage = QString("[Alert %1] %2")
                           .arg(severity)
                           .arg(QString::fromStdString(message));
    logToTerminal(qMessage);
}

// --------------------------------------------------
// Helper Methods
// --------------------------------------------------

// Append text to the terminal-like QTextEdit
void MainWindow::logToTerminal(const QString &text)
{
    // Move cursor to the end and insert text with a newline
    terminalView->append(text);

    // Auto-scroll to the bottom
    QTextCursor cursor = terminalView->textCursor();
    cursor.movePosition(QTextCursor::End);
    terminalView->setTextCursor(cursor);
}

// Refresh blacklist view in listView
void MainWindow::refreshBlacklistView()
{
    listView->clear();
    for (const string &ip : blacklist)
    {
        listView->addItem(QString::fromStdString(ip));
    }
}

// Refresh network graph view in listView
void MainWindow::refreshNetworkGraphView()
{
    listView->clear();

    // For each source IP, list all destinations
    for (const auto &entry : networkGraph)
    {
        const string &source = entry.first;
        const vector<string> &dests = entry.second;

        for (const string &dest : dests)
        {
            QString line = QString::fromStdString(source + " -> " + dest);
            listView->addItem(line);
        }
    }
}

// Refresh alerts view in listView
void MainWindow::refreshAlertsView()
{
    listView->clear();

    // Copy the priority queue so we don't destroy the original
    priority_queue<Alert, vector<Alert>, AlertCompare> copyQueue = alertQueue;

    while (!copyQueue.empty())
    {
        Alert a = copyQueue.top();
        copyQueue.pop();

        QString line = QString("[Severity %1] %2")
                           .arg(a.severity)
                           .arg(QString::fromStdString(a.message));
        listView->addItem(line);
    }
}

// Choose an IP from the network graph to block
string MainWindow::chooseIpToBlock()
{
    // Simple strategy: pick the first key in the map
    if (networkGraph.empty())
        return "";

    auto it = networkGraph.begin();
    return it->first;
}
