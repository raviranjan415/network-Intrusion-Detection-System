#ifndef MAINWINDOW_H
#define MAINWINDOW_H

// Qt headers for GUI
#include <QMainWindow>
#include <QTextEdit>
#include <QPushButton>
#include <QListWidget>
#include <QTimer>
#include <QLabel>
#include <QWidget>

// C++ Standard Library headers
#include <queue>
#include <unordered_set>
#include <set>
#include <map>
#include <vector>
#include <stack>
#include <string>
#include <random>

using namespace std; // As requested (beginner-friendly, though not best practice in big projects)

// -------------------------
// Simple Packet Definition
// -------------------------
struct Packet
{
    string sourceIp;
    string destinationIp;
    int port;
    string data;
};

// -------------------------
// Alert Structure
// -------------------------
struct Alert
{
    string message;     // Human-readable description of the alert
    int severity;       // 1 = Low, 2 = Medium, 3 = High, 4 = Critical
    string sourceIp;    // IP address related to this alert
};

// Comparator for priority_queue (higher severity = higher priority)
struct AlertCompare
{
    bool operator()(const Alert &a, const Alert &b) const
    {
        // Return true if "a" is lower priority than "b"
        // This makes the priority_queue put the highest severity on top
        return a.severity < b.severity;
    }
};

// -------------------------
// Simple Trie Node
// -------------------------
class TrieNode
{
public:
    // Each node can have up to 26 children (A-Z) for simplicity
    TrieNode *children[26];
    bool isEndOfWord;

    TrieNode()
    {
        // Initialize all children to nullptr and isEndOfWord to false
        for (int i = 0; i < 26; ++i)
        {
            children[i] = nullptr;
        }
        isEndOfWord = false;
    }
};

// -------------------------
// Simple Trie (Prefix Tree)
// -------------------------
// This Trie is used to store "bad words" like ATTACK or VIRUS.
// Later, we can search packet data to see if any of these words appear.
class Trie
{
public:
    Trie()
    {
        root = new TrieNode();
    }

    // Insert a word into the Trie (assuming word is uppercase A-Z)
    void insert(const string &word)
    {
        TrieNode *node = root;
        for (char c : word)
        {
            if (c < 'A' || c > 'Z')
                continue; // Skip any non A-Z characters just in case

            int index = c - 'A';
            if (node->children[index] == nullptr)
            {
                node->children[index] = new TrieNode();
            }
            node = node->children[index];
        }
        node->isEndOfWord = true;
    }

    // Check if any bad word exists inside the given text
    // We do a simple search: for each position, try to follow the Trie
    bool containsBadWord(const string &text)
    {
        // Convert text to uppercase to match how we inserted words
        string upper = text;
        for (char &c : upper)
        {
            if (c >= 'a' && c <= 'z')
                c = static_cast<char>(c - 'a' + 'A');
        }

        int n = static_cast<int>(upper.size());
        for (int i = 0; i < n; ++i)
        {
            TrieNode *node = root;
            int j = i;
            // Try to follow from position i forward
            while (j < n && node != nullptr)
            {
                char c = upper[j];
                if (c < 'A' || c > 'Z')
                    break; // Stop if not an uppercase letter

                int index = c - 'A';
                node = node->children[index];
                if (node == nullptr)
                    break;

                if (node->isEndOfWord)
                {
                    // Found a complete bad word
                    return true;
                }
                ++j;
            }
        }
        return false;
    }

private:
    TrieNode *root; // Root node of the Trie
};

// -------------------------
// Main Window Declaration
// -------------------------
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Sidebar button actions
    void onStartScanClicked();
    void onViewBlacklistClicked();
    void onNetworkGraphClicked();
    void onAlertsClicked();

    // Control button actions
    void onSimulateTrafficClicked();
    void onBlockIpClicked();
    void onUndoBlockClicked();

    // Timer slot to process packets periodically
    void onProcessNextPacket();

private:
    // Helper methods to build UI and logic
    void setupUi();
    void setupStyles();
    void setupDataStructures();

    Packet generateRandomPacket();
    void enqueuePacket(const Packet &packet);
    void scanPacket(const Packet &packet);

    void logToTerminal(const QString &text);

    void refreshBlacklistView();
    void refreshNetworkGraphView();
    void refreshAlertsView();

    string chooseIpToBlock();

    // -------------------------
    // UI Elements
    // -------------------------
    QTextEdit *terminalView;      // Terminal-like text area at the bottom
    QListWidget *listView;        // List widget to show blacklist / graph / alerts
    QLabel *listTitleLabel;       // Title above the list view

    QPushButton *startScanButton;
    QPushButton *viewBlacklistButton;
    QPushButton *networkGraphButton;
    QPushButton *alertsButton;

    QPushButton *simulateTrafficButton;
    QPushButton *blockIpButton;
    QPushButton *undoBlockButton;

    QTimer *scanTimer;            // Timer to process packet queue

    // -------------------------
    // Data Structures
    // -------------------------
    queue<Packet> packetQueue;                                     // 1. Queue of incoming packets
    unordered_set<string> blacklist;                               // 2. Hash table for blacklisted IPs
    set<int> protectedPorts;                                       // 3. BST of protected ports
    map<string, vector<string>> networkGraph;                      // 4. Graph of who talks to whom
    priority_queue<Alert, vector<Alert>, AlertCompare> alertQueue; // 5. Priority queue for alerts
    Trie badWordTrie;                                              // 6. Trie for bad words
    stack<string> undoBlockedIps;                                  // 7. Stack for undo last blocked IP

    // -------------------------
    // State
    // -------------------------
    bool scanning; // True if Start Scan has been pressed
};

#endif // MAINWINDOW_H
