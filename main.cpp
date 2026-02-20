#include <QApplication>
#include "mainwindow.h"

// This is the entry point of the Qt application
int main(int argc, char *argv[])
{
    // QApplication is required for any Qt GUI application
    QApplication a(argc, argv);

    // Create our main window
    MainWindow w;

    // Show the main window on the screen
    w.show();

    // Start the Qt event loop (waits for button clicks, timers, etc.)
    return a.exec();
}
