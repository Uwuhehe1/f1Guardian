const { app, BrowserWindow, shell } = require('electron');
const path = require('path');

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 900,
    minHeight: 600,
    autoHideMenuBar: true,     // hides the top menu for a cleaner look
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      devTools: false           // <<< disable DevTools entirely (optional)
    }
  });

  // DON'T auto-open devtools:
  // mainWindow.webContents.openDevTools();   // <-- delete or comment out

  mainWindow.loadURL('http://127.0.0.1:5000/');

  // Optional: re-enable DevTools only in development
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.setDevToolsWebContents(null);
    // mainWindow.webContents.openDevTools(); // only if you really need it
  }
}

app.whenReady().then(createWindow);
