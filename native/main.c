/*
 * SailHighSea WinProcessKiller (native) - pick Windows processes and services and keep them dead.
 *
 * Pure C + Win32. Click a process or service in the list and choose "Kill & Watch": it is
 * terminated now and a small background monitor terminates it again every time it starts.
 *
 * Build: see build.sh (mingw-w64). 64-bit only. Needs administrator.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <evntrace.h>
#include <evntcons.h>
#define SECURITY_WIN32
#include <security.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>

#define APP_NAME L"SailHighSea WinProcessKiller"
#ifndef APP_VERSION
#define APP_VERSION L"dev"
#endif
#define SCAN_MS 500          /* monitor interval */
#define NOTIFY_GAP_MS 15000  /* at most one pop-up per rule in this time */

enum { IDC_TOGGLE = 101, IDC_WATCH, IDC_KILL, IDC_ADD, IDC_NOTIFY, IDC_OPTIONS, IDC_SEARCH, IDC_LIST, IDC_STATUS };
#define IDC_DLG_1 601
enum { IDM_REFRESH = 201, IDM_FOLDER, IDM_ABOUT, IDM_OPENLOG, IDM_LOCATION, IDM_COPYNAME,
       IDM_ROW_WATCH, IDM_ROW_UNWATCH, IDM_ROW_KILL };
enum { IDM_KILLLOG = 250, IDM_HISTORY, IDM_HISTREC, IDM_HOTKEY };
enum { IDC_LOG_LIST = 701, IDC_LOG_UNWATCH, IDC_LOG_COPY, IDC_LOG_CLEAR };
enum { IDM_AUTOSTART = 210, IDM_STARTMIN, IDM_CLOSETRAY, IDM_MINTRAY, IDM_ONTOP, IDM_ONLYRUN, IDM_SHOWPROC,
       IDM_SHOWSVC, IDM_AUTOMON, IDM_THEME_DARK = 220, IDM_THEME_LIGHT, IDM_THEME_SYSTEM,
       IDM_HL_WATCHED = 230, IDM_HL_SYSTEM = 232,
       IDT_SHOW = 401, IDT_MONITOR, IDT_NOTIFY, IDT_EXIT };
#define TIMER_REFRESH 7
#define TIMER_TRAY 8
#define IDI_APP 100
#define WM_TRAY (WM_APP + 3)
#define WM_SHOWME (WM_APP + 4)
#define WM_APP_KILLED (WM_APP + 5)

#define HL_WATCHED 1u
#define HL_SYSTEM 4u
enum { K_PROC = 0, K_SVC = 1 };
enum { G_WATCH = 0, G_APPS, G_BG, G_WIN, G_SVC, G_COUNT };   /* list groups, in display order */

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */
/* A watch-list entry. id = exe file name (process) or service key name (service). */
typedef struct { int kind; wchar_t id[MAX_PATH]; wchar_t label[MAX_PATH]; wchar_t path[MAX_PATH];
                 unsigned kills; DWORD lastErr; DWORD lastNotify; } Rule;
/* One row in the list. */
typedef struct { int kind; wchar_t id[MAX_PATH]; wchar_t name[MAX_PATH]; wchar_t detail[MAX_PATH];
                 BOOL watched, running, system, shared, havePath, hasWin, hasStats; double cpu, io; unsigned long long mem; int group, count, icon; unsigned kills; DWORD lastErr; } Item;

static HINSTANCE g_inst;
static HWND g_hwnd, g_list, g_search, g_status, g_bToggle, g_bWatch, g_bKill, g_bAdd, g_bNotify, g_bOptions;
static HBRUSH g_bgBrush, g_editBrush;
static HFONT g_font, g_fontBold;
static wchar_t g_dataDir[MAX_PATH], g_rulesFile[MAX_PATH], g_iniFile[MAX_PATH], g_winDir[MAX_PATH], g_selfName[MAX_PATH];

static Rule *g_rules; static int g_nrules, g_caprules;
static Item *g_items; static int g_nitems, g_capitems;
static int *g_view; static int g_nview;
static CRITICAL_SECTION g_cs;                       /* guards g_rules and g_once */
typedef struct { int kind; wchar_t id[MAX_PATH]; wchar_t path[MAX_PATH]; } OnceReq;
#define ONCE_MAX 64
static OnceReq *g_once; static int g_nonce;     /* heap, so the exe does not carry the empty arrays */
static HANDLE g_evStop, g_evKick, g_thread;
static volatile LONG g_paused;                      /* 1 = monitoring off */
static volatile LONG g_totalKills;

static int g_sortCol = -1; static BOOL g_sortAsc = TRUE;
static wchar_t g_statusText[300]; static int g_sepX, g_sepY0, g_sepY1;
static unsigned g_collapsed; static int g_groupCount[G_COUNT];
static BOOL g_startMin, g_closeTray = TRUE, g_minTray, g_onTop, g_onlyRun, g_showProc = TRUE, g_showSvc = TRUE;
static BOOL g_autoMon = TRUE, g_notify = TRUE, g_quit, g_wantMax, g_refreshPending;
static HICON g_iconBig, g_iconSmall, g_iconSmallOff;
static HIMAGELIST g_sysIL;
static RECT g_searchBox;
static NOTIFYICONDATAW g_nid; static UINT g_taskbarCreated; static BOOL g_trayOk; static int g_trayTries;
static int g_autoCache = -1;
static COLORREF cBg, cPanel, cText, cDim, cGreen, cRed, cLine, cAmber;
static BOOL g_dark = TRUE;
static int g_theme = 2;       /* 0 dark, 1 light, 2 follow system */
static int g_hotRow = -1;
static unsigned g_hl = 5;
static int g_svcIcon = -1;
static HWND g_logWnd;                 /* kill log window, NULL when closed */
static HWND g_histWnd, g_histList, g_histEdit;   /* process history window */
static BOOL g_histRec;                /* setting: record process history */
#define HOTKEY_ID 77
static UINT g_hkMods, g_hkVk;         /* global shortcut that shows the window (MOD_* flags + virtual key; 0 = none) */
static void HotkeyText(UINT mods, UINT vk, wchar_t *o, size_t cap);
static BOOL g_etwRunning;             /* the event trace is live */
static void LogWndRefresh(void);
#define COL_BG cBg
#define COL_PANEL cPanel
#define COL_TEXT cText
#define COL_DIM cDim
#define COL_GREEN cGreen
#define COL_RED cRed
#define COL_LINE cLine

static void ThemeCtl(HWND c) { SetWindowTheme(c, g_dark ? L"DarkMode_Explorer" : L"Explorer", NULL); }
static BOOL MonitorOn(void) { return InterlockedCompareExchange(&g_paused, 0, 0) == 0; }

/* ------------------------------------------------------------------ */
/* Debug log (debug-log.txt next to the exe) - for bug reports         */
/* Only program / service names are logged, never full paths.          */
/* ------------------------------------------------------------------ */
static wchar_t g_logFile[MAX_PATH];
static CRITICAL_SECTION g_logCs;
static BOOL g_logReady;

static void Log(const wchar_t *fmt, ...)
{
    wchar_t body[1024], line[1100]; char u8[3400]; va_list ap; SYSTEMTIME st; int n; HANDLE f; DWORD wr;
    if (!g_logReady) return;
    va_start(ap, fmt); _vsnwprintf(body, 1024, fmt, ap); va_end(ap);
    body[1023] = 0;
    GetLocalTime(&st);
    swprintf(line, 1100, L"%04d-%02d-%02d %02d:%02d:%02d.%03d [%lu] %ls\r\n", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, (unsigned long)GetCurrentThreadId(), body);
    n = WideCharToMultiByte(CP_UTF8, 0, line, -1, u8, sizeof u8, NULL, NULL);
    if (n <= 1) return;
    EnterCriticalSection(&g_logCs);
    f = CreateFileW(g_logFile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) { WriteFile(f, u8, (DWORD)(n - 1), &wr, NULL); CloseHandle(f); }
    LeaveCriticalSection(&g_logCs);
}

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS *ep)
{
    void *frames[24]; USHORT nf, i; ULONG_PTR base = (ULONG_PTR)GetModuleHandleW(NULL);
    Log(L"*** CRASH: exception 0x%08lX at exe+0x%llX", (unsigned long)ep->ExceptionRecord->ExceptionCode,
        (unsigned long long)((ULONG_PTR)ep->ExceptionRecord->ExceptionAddress - base));
    nf = CaptureStackBackTrace(0, 24, frames, NULL);
    for (i = 0; i < nf; i++) Log(L"    frame %u: exe+0x%llX", i, (unsigned long long)((ULONG_PTR)frames[i] - base));
    Log(L"*** Please attach this file (debug-log.txt) to your bug report.");
    return EXCEPTION_CONTINUE_SEARCH;
}

static void LogInit(LPCWSTR cmd)
{
    WIN32_FILE_ATTRIBUTE_DATA fa; wchar_t old[MAX_PATH]; DWORD major = 0, minor = 0, build = 0;
    typedef LONG (WINAPI *RtlGetVersionFn)(OSVERSIONINFOW *);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll"); RtlGetVersionFn rgv = nt ? (RtlGetVersionFn)GetProcAddress(nt, "RtlGetVersion") : NULL;
    InitializeCriticalSection(&g_logCs);
    swprintf(g_logFile, MAX_PATH, L"%ls\\debug-log.txt", g_dataDir);
    if (GetFileAttributesExW(g_logFile, GetFileExInfoStandard, &fa) && fa.nFileSizeHigh == 0 && fa.nFileSizeLow > 1024 * 1024) {
        swprintf(old, MAX_PATH, L"%ls\\debug-log.old.txt", g_dataDir);
        MoveFileExW(g_logFile, old, MOVEFILE_REPLACE_EXISTING);
    }
    g_logReady = TRUE;
    SetUnhandledExceptionFilter(CrashFilter);
    if (rgv) { OSVERSIONINFOW vi; ZeroMemory(&vi, sizeof vi); vi.dwOSVersionInfoSize = sizeof vi; if (rgv(&vi) == 0) { major = vi.dwMajorVersion; minor = vi.dwMinorVersion; build = vi.dwBuildNumber; } }
    Log(L"==== %ls v%ls started (Windows %lu.%lu build %lu, admin=%d, args=\"%ls\") ====", APP_NAME, APP_VERSION,
        (unsigned long)major, (unsigned long)minor, (unsigned long)build, (int)IsUserAnAdmin(), cmd ? cmd : L"");
}

/* ------------------------------------------------------------------ */
/* Flat, rounded, owner-drawn buttons (GDI+ for anti-aliased corners)  */
/* ------------------------------------------------------------------ */
typedef struct GpGraphics GpGraphics;
typedef struct GpPath GpPath;
typedef struct GpBrush GpBrush;
typedef struct { UINT32 GdiplusVersion; void *DebugEventCallback; BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs; } GdipStartupInput;
int WINAPI GdiplusStartup(ULONG_PTR *token, const GdipStartupInput *in, void *out);
int WINAPI GdipCreateFromHDC(HDC dc, GpGraphics **g);
int WINAPI GdipDeleteGraphics(GpGraphics *g);
int WINAPI GdipSetSmoothingMode(GpGraphics *g, int mode);
int WINAPI GdipCreatePath(int fillMode, GpPath **p);
int WINAPI GdipAddPathArc(GpPath *p, float x, float y, float w, float h, float start, float sweep);
int WINAPI GdipClosePathFigure(GpPath *p);
int WINAPI GdipDeletePath(GpPath *p);
int WINAPI GdipCreateSolidFill(UINT32 argb, GpBrush **b);
int WINAPI GdipDeleteBrush(GpBrush *b);
int WINAPI GdipFillPath(GpGraphics *g, GpBrush *b, GpPath *p);

static ULONG_PTR g_gdipToken;
static void StartGdip(void)
{
    GdipStartupInput in; ZeroMemory(&in, sizeof in); in.GdiplusVersion = 1;
    GdiplusStartup(&g_gdipToken, &in, NULL);
}

static void FillRounded(HDC dc, const RECT *r, int radius, COLORREF c)
{
    GpGraphics *g = NULL; GpPath *p = NULL; GpBrush *b = NULL;
    float x = (float)r->left, y = (float)r->top, w = (float)(r->right - r->left - 1), h = (float)(r->bottom - r->top - 1), d = (float)radius * 2;
    if (GdipCreateFromHDC(dc, &g) != 0 || !g) { HBRUSH hb = CreateSolidBrush(c); FillRect(dc, r, hb); DeleteObject(hb); return; }
    GdipSetSmoothingMode(g, 4 /* AntiAlias */);
    GdipCreatePath(0, &p);
    GdipAddPathArc(p, x, y, d, d, 180, 90);
    GdipAddPathArc(p, x + w - d, y, d, d, 270, 90);
    GdipAddPathArc(p, x + w - d, y + h - d, d, d, 0, 90);
    GdipAddPathArc(p, x, y + h - d, d, d, 90, 90);
    GdipClosePathFigure(p);
    GdipCreateSolidFill(0xFF000000u | (GetRValue(c) << 16) | (GetGValue(c) << 8) | GetBValue(c), &b);
    GdipFillPath(g, b, p);
    GdipDeleteBrush(b); GdipDeletePath(p); GdipDeleteGraphics(g);
}

static LRESULT CALLBACK FlatBtnProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)id; (void)ref;
    if (m == WM_MOUSEMOVE && !GetPropW(h, L"hov")) {
        TRACKMOUSEEVENT t = {sizeof t, TME_LEAVE, h, 0};
        SetPropW(h, L"hov", (HANDLE)1); TrackMouseEvent(&t); InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_MOUSELEAVE) {
        RemovePropW(h, L"hov"); InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_NCDESTROY) {
        RemovePropW(h, L"hov"); RemoveWindowSubclass(h, FlatBtnProc, 7);
    }
    return DefSubclassProc(h, m, w, l);
}

static void FlatButton(HWND b) { SetWindowSubclass(b, FlatBtnProc, 7, 0); }

static void DrawFlatButton(const DRAWITEMSTRUCT *di)
{
    RECT r = di->rcItem; wchar_t t[96]; COLORREF fill, txt;
    BOOL down = (di->itemState & ODS_SELECTED) != 0, hot = GetPropW(di->hwndItem, L"hov") != NULL;
    BOOL danger = di->CtlID == IDC_KILL;
    BOOL accent = di->CtlID == IDC_TOGGLE || di->CtlID == IDC_WATCH || di->CtlID == IDC_DLG_1 || (di->CtlID == IDC_NOTIFY && g_notify) || danger;
    UINT dpi = GetDpiForWindow(di->hwndItem);
    int radius = MulDiv(8, (int)dpi, 96);
    HBRUSH bg = CreateSolidBrush(cBg);
    FillRect(di->hDC, &r, bg); DeleteObject(bg);
    if (accent) {
        BOOL green = (di->CtlID == IDC_TOGGLE && MonitorOn()) || di->CtlID == IDC_NOTIFY;
        if (danger)     fill = down ? RGB(153, 27, 27) : hot ? RGB(239, 68, 68) : RGB(220, 38, 38);
        else if (green) fill = down ? RGB(21, 128, 61) : hot ? RGB(34, 197, 94) : RGB(22, 163, 74);
        else            fill = down ? RGB(29, 78, 200) : hot ? RGB(59, 130, 246) : RGB(37, 99, 235);
        txt = RGB(255, 255, 255);
    } else {
        if (g_dark) fill = down ? RGB(88, 88, 102) : hot ? RGB(74, 74, 88) : RGB(50, 50, 58);
        else        fill = down ? RGB(190, 190, 208) : hot ? RGB(206, 206, 222) : RGB(226, 226, 235);
        txt = cText;
    }
    FillRounded(di->hDC, &r, radius, fill);
    GetWindowTextW(di->hwndItem, t, 96);
    HGDIOBJ of = SelectObject(di->hDC, g_font);
    SetBkMode(di->hDC, TRANSPARENT); SetTextColor(di->hDC, txt);
    if (down) OffsetRect(&r, 0, 1);
    DrawTextW(di->hDC, t, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);
    SelectObject(di->hDC, of);
}

/* Loads the app icon at exactly px x px (the .ico has 16..256), so it is never stretched. */
static HICON IconAtSize(int px, HICON *cache, int *cacheSz)
{
    if (*cacheSz != px) {
        if (*cache) DestroyIcon(*cache);
        *cache = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, px, px, LR_DEFAULTCOLOR);
        *cacheSz = px;
    }
    return *cache;
}

/* Grey copy of an icon: the tray icon while monitoring is paused. */
static HICON TintGray(HICON src)
{
    ICONINFO ii; BITMAP bm; HICON out = NULL;
    if (!src || !GetIconInfo(src, &ii)) return NULL;
    if (ii.hbmColor && GetObjectW(ii.hbmColor, sizeof bm, &bm) && bm.bmWidth > 0 && bm.bmHeight > 0) {
        int w = bm.bmWidth, h = bm.bmHeight; BITMAPINFO bi; void *bits = NULL; HDC dc = GetDC(NULL); HBITMAP nb, orig = ii.hbmColor;
        ZeroMemory(&bi, sizeof bi);
        bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
        nb = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
        if (nb && bits && GetDIBits(dc, orig, 0, (UINT)h, bits, &bi, DIB_RGB_COLORS) == h) {
            BYTE *px = (BYTE *)bits;
            for (int i = 0; i < w * h; i++, px += 4) {
                int lum = (px[2] * 30 + px[1] * 59 + px[0] * 11) / 100;
                if (px[3] == 255 || px[3] == 0) lum = 70 + lum * 65 / 100;
                if (lum > 255) lum = 255;
                px[0] = px[1] = px[2] = (BYTE)lum;
            }
            ii.hbmColor = nb;
            out = CreateIconIndirect(&ii);
        }
        if (nb) DeleteObject(nb);
        ReleaseDC(NULL, dc);
        ii.hbmColor = orig;
    }
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask) DeleteObject(ii.hbmMask);
    return out;
}

/* ------------------------------------------------------------------ */
/* Modern message dialog (themed, flat rounded buttons)                */
/* ------------------------------------------------------------------ */
static int g_dlgResult; static BOOL g_dlgDone; static const wchar_t *g_dlgText;

static LRESULT CALLBACK DlgProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_COMMAND:
        if (LOWORD(w) >= IDC_DLG_1 && LOWORD(w) <= IDC_DLG_1 + 2) { g_dlgResult = LOWORD(w) - IDC_DLG_1 + 1; g_dlgDone = TRUE; DestroyWindow(h); }
        return 0;
    case WM_CLOSE:
        g_dlgResult = 0; g_dlgDone = TRUE; DestroyWindow(h);
        return 0;
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_ERASEBKGND: {
        RECT rc; HBRUSH b = CreateSolidBrush(cBg); GetClientRect(h, &rc); FillRect((HDC)w, &rc, b); DeleteObject(b);
        return 1;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc, tr; UINT dpi = GetDpiForWindow(h);
        int mg = MulDiv(20, (int)dpi, 96), ic = MulDiv(32, (int)dpi, 96);
        HGDIOBJ of = SelectObject(dc, g_font);
        GetClientRect(h, &rc);
        { static HICON ci; static int cs; HICON hi = IconAtSize(ic, &ci, &cs);
          if (hi) DrawIconEx(dc, mg, mg, hi, ic, ic, 0, NULL, DI_NORMAL); }
        tr.left = mg + ic + mg; tr.top = mg; tr.right = rc.right - mg; tr.bottom = rc.bottom;
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, cText);
        DrawTextW(dc, g_dlgText, -1, &tr, DT_WORDBREAK | DT_NOPREFIX);
        SelectObject(dc, of);
        EndPaint(h, &ps);
        return 0;
    }
    }
    return DefWindowProcW(h, m, w, l);
}

/* Returns 1..3 for the pressed button, 0 if closed (Esc / X). */
static int ShowDialog(HWND owner, const wchar_t *title, const wchar_t *text, const wchar_t *b1, const wchar_t *b2, const wchar_t *b3)
{
    const wchar_t *labels[3] = {b1, b2, b3}; int n = 0;
    static BOOL registered;
    BOOL ownerOk = owner && IsWindowVisible(owner) && !IsIconic(owner);
    UINT dpi = ownerOk ? GetDpiForWindow(owner) : GetDpiForSystem();
    #define DP(v) MulDiv((v), (int)dpi, 96)
    int mg = DP(20), ic = DP(32), cw = DP(500), bw = DP(120), bh = DP(34), gap = DP(8);
    RECT tr = {0, 0, cw - 3 * mg - ic, 0}, wr, wa; HDC dc; HGDIOBJ of; int ch, W, H;
    HWND dlg; MSG msg; BOOL dark = g_dark;
    DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU, ex = ownerOk ? 0 : WS_EX_TOPMOST;
    if (!registered) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = DlgProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSWPKDlg";
        RegisterClassW(&wc); registered = TRUE;
    }
    dc = GetDC(NULL); of = SelectObject(dc, g_font);
    DrawTextW(dc, text, -1, &tr, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    SelectObject(dc, of); ReleaseDC(NULL, dc);
    ch = mg + (tr.bottom > ic ? tr.bottom : ic) + mg + bh + mg;
    wr.left = 0; wr.top = 0; wr.right = cw; wr.bottom = ch;
    AdjustWindowRectExForDpi(&wr, style, FALSE, ex, dpi);
    W = wr.right - wr.left; H = wr.bottom - wr.top;
    if (ownerOk) GetWindowRect(owner, &wa); else SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    g_dlgText = text; g_dlgResult = 0; g_dlgDone = FALSE;
    dlg = CreateWindowExW(ex, L"SHSWPKDlg", title, style, wa.left + (wa.right - wa.left - W) / 2, wa.top + (wa.bottom - wa.top - H) / 2, W, H,
                          ownerOk ? owner : NULL, NULL, g_inst, NULL);
    if (!dlg) return 0;
    if (g_iconSmall) SendMessageW(dlg, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    if (g_iconBig) SendMessageW(dlg, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    DwmSetWindowAttribute(dlg, 20, &dark, sizeof dark);
    { int pref = 2; DwmSetWindowAttribute(dlg, 33, &pref, sizeof pref); }
    for (int i = 0; i < 3; i++) if (labels[i]) n++;
    { int x = cw - mg - n * bw - (n - 1) * gap, k = 0;
      for (int i = 0; i < 3; i++) {
        HWND b; if (!labels[i]) continue;
        b = CreateWindowExW(0, L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, x + k * (bw + gap), ch - mg - bh, bw, bh, dlg, (HMENU)(INT_PTR)(IDC_DLG_1 + i), g_inst, NULL);
        SendMessageW(b, WM_SETFONT, (WPARAM)g_font, TRUE);
        FlatButton(b); k++;
      } }
    if (ownerOk) EnableWindow(owner, FALSE);
    ShowWindow(dlg, SW_SHOW); SetForegroundWindow(dlg);
    while (!g_dlgDone && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) { SendMessageW(dlg, WM_CLOSE, 0, 0); continue; }
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && GetAncestor(msg.hwnd, GA_ROOT) == dlg) { SendMessageW(dlg, WM_COMMAND, IDC_DLG_1, 0); continue; }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    if (ownerOk) { EnableWindow(owner, TRUE); SetForegroundWindow(owner); }
    #undef DP
    return g_dlgResult;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */
static const wchar_t *BaseName(const wchar_t *p)
{
    const wchar_t *s = wcsrchr(p, L'\\');
    return s ? s + 1 : p;
}

static BOOL ContainsNoCase(const wchar_t *hay, const wchar_t *needle)
{
    size_t n = wcslen(needle);
    if (!n) return TRUE;
    for (; *hay; hay++)
        if (_wcsnicmp(hay, needle, n) == 0) return TRUE;
    return FALSE;
}

static void InitPaths(void)
{
    /* Portable: settings and the watch list live next to the executable. */
    wchar_t *slash;
    GetModuleFileNameW(NULL, g_dataDir, MAX_PATH);
    wcscpy(g_selfName, BaseName(g_dataDir));
    slash = wcsrchr(g_dataDir, L'\\');
    if (slash) *slash = 0;
    swprintf(g_rulesFile, MAX_PATH, L"%ls\\watch-list.txt", g_dataDir);
    swprintf(g_iniFile, MAX_PATH, L"%ls\\settings.ini", g_dataDir);
}

static void LoadSettings(void)
{
    #define GI(k, d) (GetPrivateProfileIntW(L"s", k, d, g_iniFile) != 0)
    g_notify = GI(L"notify", 1); g_autoMon = GI(L"automon", 1);
    g_startMin = GI(L"startmin", 0); g_closeTray = GI(L"closetray", 1); g_minTray = GI(L"mintray", 0); g_onTop = GI(L"ontop", 0);
    g_histRec = GI(L"history", 0); g_hkMods = GetPrivateProfileIntW(L"s", L"hkmods", 0, g_iniFile); g_hkVk = GetPrivateProfileIntW(L"s", L"hkvk", 0, g_iniFile); g_onlyRun = GI(L"onlyrun", 0); g_showProc = GI(L"showproc", 1); g_showSvc = GI(L"showsvc", 1);
    #undef GI
    g_theme = (int)GetPrivateProfileIntW(L"s", L"theme", 2, g_iniFile);
    if (g_theme < 0 || g_theme > 2) g_theme = 2;
    g_hl = GetPrivateProfileIntW(L"s", L"hl", 5, g_iniFile) & (HL_WATCHED | HL_SYSTEM);
    g_collapsed = GetPrivateProfileIntW(L"s", L"collapsed", 0, g_iniFile) & ((1u << G_COUNT) - 1);
}

static void SaveSettings(void)
{
    wchar_t n[16];
    #define PB(k, v) WritePrivateProfileStringW(L"s", k, (v) ? L"1" : L"0", g_iniFile)
    PB(L"notify", g_notify); PB(L"automon", g_autoMon); PB(L"startmin", g_startMin); PB(L"closetray", g_closeTray);
    PB(L"mintray", g_minTray); PB(L"ontop", g_onTop); PB(L"onlyrun", g_onlyRun);
    PB(L"history", g_histRec); PB(L"showproc", g_showProc); PB(L"showsvc", g_showSvc);
    #undef PB
    swprintf(n, 16, L"%u", g_hkMods); WritePrivateProfileStringW(L"s", L"hkmods", n, g_iniFile);
    swprintf(n, 16, L"%u", g_hkVk); WritePrivateProfileStringW(L"s", L"hkvk", n, g_iniFile);
    swprintf(n, 16, L"%d", g_theme); WritePrivateProfileStringW(L"s", L"theme", n, g_iniFile);
    swprintf(n, 16, L"%u", g_hl); WritePrivateProfileStringW(L"s", L"hl", n, g_iniFile);
    swprintf(n, 16, L"%u", g_collapsed); WritePrivateProfileStringW(L"s", L"collapsed", n, g_iniFile);
}

/* ------------------------------------------------------------------ */
/* Protection: things that must never be killed                        */
/* ------------------------------------------------------------------ */
static BOOL IsProtectedProc(const wchar_t *name)
{
    static const wchar_t *p[] = { L"system", L"system idle process", L"registry", L"smss.exe", L"csrss.exe", L"wininit.exe",
        L"winlogon.exe", L"services.exe", L"lsass.exe", L"lsm.exe", L"dwm.exe", L"svchost.exe", L"fontdrvhost.exe",
        L"memcompression", L"secure system", L"explorer.exe" };
    if (_wcsicmp(name, g_selfName) == 0) return TRUE;
    for (size_t i = 0; i < sizeof p / sizeof p[0]; i++) if (_wcsicmp(name, p[i]) == 0) return TRUE;
    return FALSE;
}

static BOOL IsProtectedSvc(const wchar_t *name)
{
    static const wchar_t *p[] = { L"RpcSs", L"RpcEptMapper", L"DcomLaunch", L"LSM", L"SamSs", L"BrokerInfrastructure",
        L"SystemEventsBroker", L"CoreMessagingRegistrar", L"Power", L"PlugPlay", L"ProfSvc" };
    for (size_t i = 0; i < sizeof p / sizeof p[0]; i++) if (_wcsicmp(name, p[i]) == 0) return TRUE;
    return FALSE;
}

static void EnableDebugPriv(void)
{
    HANDLE tok; TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(tok);
    Log(L"SeDebugPrivilege: %ls", GetLastError() == ERROR_SUCCESS ? L"enabled" : L"not available");
}

/* ------------------------------------------------------------------ */
/* Watch list (watch-list.txt: kind <TAB> id <TAB> label <TAB> path)   */
/* ------------------------------------------------------------------ */
static wchar_t *ReadTextFile(const wchar_t *path)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD sz, got = 0; char *raw; wchar_t *out; int n;
    if (f == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(f, NULL);
    if (sz == INVALID_FILE_SIZE || sz > 8 * 1024 * 1024) { CloseHandle(f); return NULL; }
    raw = (char *)malloc(sz + 1);
    if (!raw) { CloseHandle(f); return NULL; }
    if (!ReadFile(f, raw, sz, &got, NULL)) got = 0;
    CloseHandle(f);
    raw[got] = 0;
    { const char *s = raw; DWORD len = got; if (len >= 3 && (BYTE)s[0] == 0xEF && (BYTE)s[1] == 0xBB && (BYTE)s[2] == 0xBF) { s += 3; len -= 3; }
      out = (wchar_t *)malloc(((size_t)len + 1) * sizeof(wchar_t));
      if (!out) { free(raw); return NULL; }
      n = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, out, (int)len);
      out[n > 0 ? n : 0] = 0; }
    free(raw);
    return out;
}

/* caller holds g_cs */
static int FindRuleIdx(int kind, const wchar_t *id)
{
    for (int i = 0; i < g_nrules; i++)
        if (g_rules[i].kind == kind && _wcsicmp(g_rules[i].id, id) == 0) return i;
    return -1;
}

/* caller holds g_cs */
static void SaveRulesLocked(void)
{
    HANDLE f = CreateFileW(g_rulesFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { Log(L"ERROR: cannot write the watch list (%lu)", (unsigned long)GetLastError()); return; }
    for (int i = 0; i < g_nrules; i++) {
        wchar_t line[MAX_PATH * 3 + 16]; char u8[MAX_PATH * 9 + 48]; int n; DWORD wr;
        swprintf(line, MAX_PATH * 3 + 16, L"%lc\t%ls\t%ls\t%ls\r\n", g_rules[i].kind == K_SVC ? L'S' : L'P', g_rules[i].id, g_rules[i].label, g_rules[i].path);
        n = WideCharToMultiByte(CP_UTF8, 0, line, -1, u8, sizeof u8, NULL, NULL);
        if (n > 1) WriteFile(f, u8, (DWORD)(n - 1), &wr, NULL);
    }
    CloseHandle(f);
}

static BOOL PushRuleLocked(int kind, const wchar_t *id, const wchar_t *label, const wchar_t *path)
{
    Rule *r;
    if (g_nrules == g_caprules) {
        int nc = g_caprules ? g_caprules * 2 : 64;
        Rule *t = (Rule *)realloc(g_rules, (size_t)nc * sizeof(Rule));
        if (!t) return FALSE;
        g_rules = t; g_caprules = nc;
    }
    r = &g_rules[g_nrules++];
    ZeroMemory(r, sizeof *r);
    r->kind = kind;
    wcsncpy(r->id, id, MAX_PATH - 1); wcsncpy(r->label, label && *label ? label : id, MAX_PATH - 1); wcsncpy(r->path, path ? path : L"", MAX_PATH - 1);
    return TRUE;
}

static void LoadRules(void)
{
    wchar_t *txt = ReadTextFile(g_rulesFile), *p, *next;
    if (!txt) return;
    EnterCriticalSection(&g_cs);
    for (p = txt; p && *p; p = next) {
        wchar_t *f[4] = {NULL, NULL, NULL, NULL}; int nf = 0; wchar_t *q;
        next = wcschr(p, L'\n');
        if (next) *next++ = 0;
        q = wcschr(p, L'\r'); if (q) *q = 0;
        f[nf++] = p;
        for (q = p; *q && nf < 4; q++) if (*q == L'\t') { *q = 0; f[nf++] = q + 1; }
        if (nf < 2 || !f[1][0] || (f[0][0] != L'P' && f[0][0] != L'S')) continue;
        { int kind = f[0][0] == L'S' ? K_SVC : K_PROC;
          if (FindRuleIdx(kind, f[1]) < 0) PushRuleLocked(kind, f[1], nf > 2 ? f[2] : f[1], nf > 3 ? f[3] : L""); }
    }
    LeaveCriticalSection(&g_cs);
    free(txt);
}

static void AddRule(int kind, const wchar_t *id, const wchar_t *label, const wchar_t *path)
{
    EnterCriticalSection(&g_cs);
    if (FindRuleIdx(kind, id) < 0 && PushRuleLocked(kind, id, label, path)) SaveRulesLocked();
    LeaveCriticalSection(&g_cs);
    if (g_evKick) SetEvent(g_evKick);
    Log(L"Watch %ls: %ls", kind == K_SVC ? L"service" : L"process", id);
}

static void RemoveRule(int kind, const wchar_t *id)
{
    EnterCriticalSection(&g_cs);
    int i = FindRuleIdx(kind, id);
    if (i >= 0) { memmove(&g_rules[i], &g_rules[i + 1], sizeof(Rule) * (size_t)(g_nrules - i - 1)); g_nrules--; SaveRulesLocked(); }
    LeaveCriticalSection(&g_cs);
    Log(L"Unwatch %ls: %ls", kind == K_SVC ? L"service" : L"process", id);
}

/* one-shot "kill it now" request for the monitor thread */
static void QueueOnce(int kind, const wchar_t *id, const wchar_t *path)
{
    EnterCriticalSection(&g_cs);
    if (!g_once) g_once = (OnceReq *)calloc(ONCE_MAX, sizeof(OnceReq));
    if (g_once && g_nonce < ONCE_MAX) {
        OnceReq *q = &g_once[g_nonce++];
        q->kind = kind; wcsncpy(q->id, id, MAX_PATH - 1); q->id[MAX_PATH - 1] = 0; wcsncpy(q->path, path ? path : L"", MAX_PATH - 1); q->path[MAX_PATH - 1] = 0;
    }
    LeaveCriticalSection(&g_cs);
    SetEvent(g_evKick);
}

/* ------------------------------------------------------------------ */
/* Monitor thread: kills watched processes and stops watched services  */
/* ------------------------------------------------------------------ */
typedef struct { int kind; wchar_t id[MAX_PATH]; wchar_t path[MAX_PATH]; BOOL once; unsigned killed; DWORD err; } Target;

static BOOL KillPid(DWORD pid, DWORD *err)
{
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    BOOL ok;
    if (!h) { *err = GetLastError(); return FALSE; }
    ok = TerminateProcess(h, 1);
    if (!ok) *err = GetLastError();
    CloseHandle(h);
    return ok;
}

static BOOL WaitSvcStopped(SC_HANDLE svc, DWORD ms, SERVICE_STATUS_PROCESS *ssp)
{
    DWORD need, t0 = GetTickCount();
    for (;;) {
        if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (BYTE *)ssp, sizeof *ssp, &need)) return FALSE;
        if (ssp->dwCurrentState == SERVICE_STOPPED) return TRUE;
        if (GetTickCount() - t0 >= ms) return FALSE;
        Sleep(150);
    }
}

static void StopDependents(SC_HANDLE scm, SC_HANDLE svc)
{
    DWORD need = 0, cnt = 0; ENUM_SERVICE_STATUSW *dep;
    EnumDependentServicesW(svc, SERVICE_ACTIVE, NULL, 0, &need, &cnt);
    if (GetLastError() != ERROR_MORE_DATA || !need) return;
    dep = (ENUM_SERVICE_STATUSW *)malloc(need);
    if (!dep) return;
    if (EnumDependentServicesW(svc, SERVICE_ACTIVE, dep, need, &need, &cnt)) {
        for (DWORD i = 0; i < cnt; i++) {
            SC_HANDLE d = OpenServiceW(scm, dep[i].lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (d) {
                SERVICE_STATUS st; SERVICE_STATUS_PROCESS sp;
                ControlService(d, SERVICE_CONTROL_STOP, &st);
                WaitSvcStopped(d, 2000, &sp);
                CloseServiceHandle(d);
            }
        }
    }
    free(dep);
}

/* TRUE if a running service was stopped now. *err is set when it could not be stopped. */
static BOOL StopServiceByName(const wchar_t *name, DWORD *err)
{
    SC_HANDLE scm, svc; SERVICE_STATUS_PROCESS ssp; DWORD need, fail = 0; BOOL did = FALSE;
    *err = 0;
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { *err = GetLastError(); return FALSE; }
    svc = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (!svc) { DWORD e = GetLastError(); if (e != ERROR_SERVICE_DOES_NOT_EXIST) *err = e; CloseServiceHandle(scm); return FALSE; }
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (BYTE *)&ssp, sizeof ssp, &need) && ssp.dwCurrentState != SERVICE_STOPPED) {
        if (ssp.dwCurrentState != SERVICE_STOP_PENDING) {
            SERVICE_STATUS st;
            StopDependents(scm, svc);
            if (!ControlService(svc, SERVICE_CONTROL_STOP, &st)) { fail = GetLastError(); if (fail == ERROR_SERVICE_NOT_ACTIVE) fail = 0; }
        }
        did = WaitSvcStopped(svc, 3000, &ssp);
        if (!did && (ssp.dwServiceType & SERVICE_WIN32_OWN_PROCESS) && ssp.dwProcessId) {
            DWORD e = 0;
            if (KillPid(ssp.dwProcessId, &e)) did = TRUE; else if (!fail) fail = e;
        }
        if (!did && !fail) fail = ERROR_SERVICE_REQUEST_TIMEOUT;
        if (did) fail = 0;
    }
    *err = fail;
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return did;
}

/* Kill log: newest first, repeats of the same item and result are merged into one row with a count. */
typedef struct { SYSTEMTIME t; int kind; BOOL fail; unsigned count; wchar_t id[MAX_PATH], label[MAX_PATH], path[MAX_PATH], result[48]; } KillEntry;
#define KLOG_MAX 500
static KillEntry *g_klog; static int g_nklog;     /* heap, allocated on first use */

/* caller holds g_cs */
static void KLogAdd(const Target *t, const wchar_t *label, const wchar_t *path, BOOL fail, const wchar_t *result)
{
    KillEntry e; int at = -1;
    if (!g_klog) g_klog = (KillEntry *)calloc(KLOG_MAX, sizeof(KillEntry));
    if (!g_klog) return;
    for (int i = 0; i < g_nklog; i++)
        if (g_klog[i].kind == t->kind && g_klog[i].fail == fail && _wcsicmp(g_klog[i].id, t->id) == 0 && wcscmp(g_klog[i].result, result) == 0) { at = i; break; }
    if (at >= 0) { e = g_klog[at]; memmove(&g_klog[1], &g_klog[0], sizeof(KillEntry) * (size_t)at); }
    else {
        ZeroMemory(&e, sizeof e);
        e.kind = t->kind; e.fail = fail;
        wcsncpy(e.id, t->id, MAX_PATH - 1); wcsncpy(e.label, label, MAX_PATH - 1); wcsncpy(e.path, path, MAX_PATH - 1); wcsncpy(e.result, result, 47);
        if (g_nklog < KLOG_MAX) g_nklog++;
        memmove(&g_klog[1], &g_klog[0], sizeof(KillEntry) * (size_t)(g_nklog - 1));
    }
    e.count += fail ? 1 : (t->killed ? t->killed : 1);
    GetLocalTime(&e.t);
    g_klog[0] = e;
}

static void ReportTarget(const Target *t)
{
    wchar_t *msg = NULL; BOOL post = FALSE;
    EnterCriticalSection(&g_cs);
    {
        int i = FindRuleIdx(t->kind, t->id); DWORD now = GetTickCount();
        const wchar_t *label = t->id, *path = t->path; BOOL speak = t->killed > 0, logFail = FALSE;
        if (i >= 0) {
            Rule *r = &g_rules[i]; label = r->label; if (r->path[0]) path = r->path;
            r->kills += t->killed;
            if (r->lastErr != t->err) { if (t->err) { Log(L"Could not stop %ls (error %lu)", r->id, (unsigned long)t->err); logFail = TRUE; } r->lastErr = t->err; post = TRUE; }
            if (t->killed) { post = TRUE; if (r->lastNotify && now - r->lastNotify < NOTIFY_GAP_MS) speak = FALSE; else r->lastNotify = now | 1; }
        } else {
            if (t->killed) post = TRUE;
            if (t->err) { Log(L"Could not stop %ls (error %lu)", t->id, (unsigned long)t->err); logFail = TRUE; post = TRUE; }
        }
        if (t->kind == K_SVC) path = t->id;
        if (t->killed) {
            wchar_t res[48]; swprintf(res, 48, L"%ls (%ls)", t->kind == K_SVC ? L"Stopped" : L"Killed", t->once ? L"manual" : L"auto");
            KLogAdd(t, label, path, FALSE, res);
        }
        if (logFail) {
            wchar_t res[48];
            if (t->err == ERROR_ACCESS_DENIED) wcscpy(res, L"Failed: access denied"); else swprintf(res, 48, L"Failed (error %lu)", (unsigned long)t->err);
            KLogAdd(t, label, path, TRUE, res);
        }
        if (speak) {
            msg = (wchar_t *)malloc(300 * sizeof(wchar_t));
            if (msg) {
                if (t->kind == K_SVC) swprintf(msg, 300, L"Stopped service %ls", label);
                else if (t->killed > 1) swprintf(msg, 300, L"Killed %ls (%u processes)", label, t->killed);
                else swprintf(msg, 300, L"Killed %ls", label);
                Log(L"%ls%ls", msg, t->once ? L" (kill once)" : L"");
            }
        }
    }
    LeaveCriticalSection(&g_cs);
    if (t->killed) InterlockedExchangeAdd(&g_totalKills, (LONG)t->killed);
    if (post && g_hwnd) { if (PostMessageW(g_hwnd, WM_APP_KILLED, 0, (LPARAM)msg)) return; }
    free(msg);
}

static void MonitorPass(void)
{
    Target *t; int nt = 0, np = 0; BOOL on = MonitorOn(); DWORD me = GetCurrentProcessId();
    EnterCriticalSection(&g_cs);
    t = (Target *)calloc((size_t)(g_nrules + g_nonce + 1), sizeof(Target));
    if (t) {
        if (on) for (int i = 0; i < g_nrules; i++) {
            if (g_rules[i].kind == K_PROC ? IsProtectedProc(g_rules[i].id) : IsProtectedSvc(g_rules[i].id)) continue;
            t[nt].kind = g_rules[i].kind; wcscpy(t[nt].id, g_rules[i].id); wcscpy(t[nt].path, g_rules[i].path); nt++;
        }
        for (int i = 0; i < g_nonce; i++) {
            if (g_once[i].kind == K_PROC ? IsProtectedProc(g_once[i].id) : IsProtectedSvc(g_once[i].id)) continue;
            { BOOL dup = FALSE; for (int k = 0; k < nt; k++) if (t[k].kind == g_once[i].kind && _wcsicmp(t[k].id, g_once[i].id) == 0) { dup = TRUE; break; } if (dup) continue; }
            t[nt].kind = g_once[i].kind; wcscpy(t[nt].id, g_once[i].id); wcscpy(t[nt].path, g_once[i].path); t[nt].once = TRUE; nt++;
        }
    }
    g_nonce = 0;
    LeaveCriticalSection(&g_cs);
    if (!t) return;
    for (int i = 0; i < nt; i++) if (t[i].kind == K_PROC) np++;
    if (np) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof pe;
            for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
                if (pe.th32ProcessID <= 4 || pe.th32ProcessID == me) continue;
                for (int i = 0; i < nt; i++) {
                    DWORD e = 0;
                    if (t[i].kind != K_PROC || _wcsicmp(pe.szExeFile, t[i].id) != 0) continue;
                    if (KillPid(pe.th32ProcessID, &e)) t[i].killed++; else t[i].err = e;
                }
            }
            CloseHandle(snap);
        }
    }
    for (int i = 0; i < nt; i++) {
        if (t[i].kind != K_SVC) continue;
        if (StopServiceByName(t[i].id, &t[i].err)) t[i].killed = 1;
    }
    for (int i = 0; i < nt; i++) {
        if (t[i].killed || t[i].err) ReportTarget(&t[i]);
        else { EnterCriticalSection(&g_cs); { int k = FindRuleIdx(t[i].kind, t[i].id); if (k >= 0 && g_rules[k].lastErr) { g_rules[k].lastErr = 0; if (g_hwnd) PostMessageW(g_hwnd, WM_APP_KILLED, 0, 0); } } LeaveCriticalSection(&g_cs); }
    }
    free(t);
}

static DWORD WINAPI MonitorThread(LPVOID p)
{
    HANDLE h[2]; (void)p;
    h[0] = g_evStop; h[1] = g_evKick;
    for (;;) {
        DWORD wait = SCAN_MS; BOOL work;
        EnterCriticalSection(&g_cs);
        work = (g_nrules > 0 && MonitorOn()) || g_nonce > 0;
        LeaveCriticalSection(&g_cs);
        if (!work) wait = 60000;      /* nothing to watch: sleep until a rule is added, monitoring resumes, or a kill is requested (all of them kick the event) */
        DWORD r = WaitForMultipleObjects(2, h, FALSE, wait);
        if (r == WAIT_OBJECT_0) break;
        MonitorPass();
    }
    return 0;
}

static void StartMonitorThread(void)
{
    g_evStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_evKick = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_thread = CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);
}

static void StopMonitorThread(void)
{
    if (!g_thread) return;
    SetEvent(g_evStop);
    WaitForSingleObject(g_thread, 8000);
    CloseHandle(g_thread); g_thread = NULL;
}

/* ------------------------------------------------------------------ */
/* Process / service list                                              */
/* ------------------------------------------------------------------ */
static void UpdateTray(void);
static void RefreshApps(void);
static BOOL g_menuOpen;

/* ------------------------------------------------------------------ */
/* CPU / memory / disk sampling per process                            */
/* ------------------------------------------------------------------ */
typedef struct { DWORD cb, PageFaultCount; SIZE_T PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage,
                 QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage, PrivateUsage, PrivateWorkingSetSize;
                 ULONG64 SharedCommitUsage; } MemEx2;   /* PROCESS_MEMORY_COUNTERS_EX2 (Windows 10 1809+) */
typedef struct { DWORD pid; ULONGLONG created, cpu, io, mem; double cpuPct, ioRate; BOOL seen; } ProcStat;
static ProcStat *g_ps; static int g_nps, g_capps;
static ULONGLONG g_psTick, g_dtMs; static BOOL g_resample; static int g_ncpu = 1;
static double g_sysCpu; static ULONGLONG g_sysIdle, g_sysKern, g_sysUser;

#define FT64(f) (((ULONGLONG)(f).dwHighDateTime << 32) | (f).dwLowDateTime)

/* Rates need two samples: only re-measure when at least 0.7 s passed, otherwise keep the last rates. */
static void BeginSample(void)
{
    ULONGLONG now = GetTickCount64(); FILETIME i, k, u;
    g_resample = g_psTick == 0 || now - g_psTick >= 700;
    g_dtMs = now - g_psTick;
    if (g_resample) g_psTick = now;
    for (int n = 0; n < g_nps; n++) g_ps[n].seen = FALSE;
    if (g_resample && GetSystemTimes(&i, &k, &u)) {
        ULONGLONG di = FT64(i) - g_sysIdle, dk = FT64(k) - g_sysKern, du = FT64(u) - g_sysUser;
        if (g_sysKern && dk + du) g_sysCpu = 100.0 * (double)(dk + du - di) / (double)(dk + du);
        g_sysIdle = FT64(i); g_sysKern = FT64(k); g_sysUser = FT64(u);
    }
}

static ProcStat *FindStat(DWORD pid)
{
    for (int n = 0; n < g_nps; n++) if (g_ps[n].pid == pid && g_ps[n].seen) return &g_ps[n];
    return NULL;
}

static ProcStat *SampleProc(DWORD pid)
{
    HANDLE h; FILETIME c, e, k, u; IO_COUNTERS io; MemEx2 m; ULONGLONG created, cpu, ioB = 0, mem = 0; ProcStat *ps = NULL;
    h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return NULL;
    if (!GetProcessTimes(h, &c, &e, &k, &u)) { CloseHandle(h); return NULL; }
    created = FT64(c); cpu = FT64(k) + FT64(u);
    if (GetProcessIoCounters(h, &io)) ioB = io.ReadTransferCount + io.WriteTransferCount;
    ZeroMemory(&m, sizeof m); m.cb = sizeof m;
    if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS *)&m, sizeof m)) mem = m.PrivateWorkingSetSize ? m.PrivateWorkingSetSize : m.WorkingSetSize;
    else { PROCESS_MEMORY_COUNTERS pm; pm.cb = sizeof pm; if (GetProcessMemoryInfo(h, &pm, sizeof pm)) mem = pm.WorkingSetSize; }
    CloseHandle(h);
    for (int n = 0; n < g_nps; n++) if (g_ps[n].pid == pid && g_ps[n].created == created) { ps = &g_ps[n]; break; }
    if (!ps) {
        if (g_nps == g_capps) {
            int nc = g_capps ? g_capps * 2 : 512; ProcStat *t = (ProcStat *)realloc(g_ps, (size_t)nc * sizeof(ProcStat));
            if (!t) return NULL;
            g_ps = t; g_capps = nc;
        }
        ps = &g_ps[g_nps++];
        ZeroMemory(ps, sizeof *ps);
        ps->pid = pid; ps->created = created; ps->cpu = cpu; ps->io = ioB;
    } else if (g_resample && g_dtMs) {
        double dt = (double)g_dtMs;
        ps->cpuPct = (double)(cpu > ps->cpu ? cpu - ps->cpu : 0) / (dt * 10000.0 * g_ncpu) * 100.0;
        if (ps->cpuPct > 100.0) ps->cpuPct = 100.0;
        ps->ioRate = (double)(ioB > ps->io ? ioB - ps->io : 0) * 1000.0 / dt;
        ps->cpu = cpu; ps->io = ioB;
    }
    ps->mem = mem; ps->seen = TRUE;
    return ps;
}

static void PruneStats(void)
{
    int w = 0;
    for (int n = 0; n < g_nps; n++) if (g_ps[n].seen) g_ps[w++] = g_ps[n];
    g_nps = w;
}

static void AddStats(Item *it, const ProcStat *ps)
{
    it->cpu += ps->cpuPct; it->io += ps->ioRate; it->mem += ps->mem; it->hasStats = TRUE;
}

static const wchar_t *CellText(const Item *it, int c)
{
    static wchar_t buf[8][40]; static int k;
    wchar_t *o = buf[k++ & 7];
    o[0] = 0;
    if (!it->hasStats) return o;
    if (c == 4) {
        if (it->cpu < 0.05) wcscpy(o, L"0%"); else swprintf(o, 40, L"%.1f%%", it->cpu);
    } else if (c == 5) {
        double mb = (double)it->mem / 1048576.0; long whole; int frac;
        if (mb < 0.05) { wcscpy(o, L"0 MB"); return o; }
        whole = (long)mb; frac = (int)((mb - (double)whole) * 10.0 + 0.5);
        if (frac == 10) { whole++; frac = 0; }
        if (whole >= 1000) swprintf(o, 40, L"%ld,%03ld.%d MB", whole / 1000, whole % 1000, frac);
        else swprintf(o, 40, L"%ld.%d MB", whole, frac);
    } else {
        double mbs = it->io / 1048576.0;
        if (mbs < 0.05) wcscpy(o, L"0 MB/s"); else swprintf(o, 40, L"%.1f MB/s", mbs);
    }
    return o;
}

/* Task-Manager-style heat map: how strongly the cell is tinted blue (percent of the tint colour). */
static int HeatPct(int c, const Item *it)
{
    static const int p[5] = {0, 14, 26, 40, 56}; int lvl;
    if (!it->hasStats) return 0;
    if (c == 4) { double v = it->cpu; lvl = v >= 50 ? 4 : v >= 25 ? 3 : v >= 5 ? 2 : v >= 0.5 ? 1 : 0; }
    else if (c == 5) { double v = (double)it->mem / 1048576.0; lvl = v >= 1024 ? 4 : v >= 500 ? 3 : v >= 150 ? 2 : v >= 50 ? 1 : 0; }
    else { double v = it->io / 1048576.0; lvl = v >= 20 ? 4 : v >= 5 ? 3 : v >= 1 ? 2 : v >= 0.1 ? 1 : 0; }
    return p[lvl];
}

static int StatusRank(const Item *x) { return x->watched ? 0 : (x->running ? 1 : 2); }

static int StatusCmp(const Item *x, const Item *y)
{
    int r = StatusRank(x) - StatusRank(y);
    if (!r) r = _wcsicmp(x->name, y->name);
    if (!r) r = x->kind - y->kind;
    return r;
}

static int ItemCmp(const void *a, const void *b)
{
    const Item *x = (const Item *)a, *y = (const Item *)b;
    int r = x->group - y->group;
    if (r) return r;                         /* groups always keep their order */
    switch (g_sortCol) {
    case 0: r = _wcsicmp(x->name, y->name); break;
    case 1: r = _wcsicmp(x->detail, y->detail); break;
    case 2: r = x->kind - y->kind; if (!r) r = _wcsicmp(x->name, y->name); break;
    case 3: r = StatusCmp(x, y); break;
    case 4: r = (y->cpu > x->cpu) - (y->cpu < x->cpu); if (!r) r = _wcsicmp(x->name, y->name); break;   /* biggest first */
    case 5: r = (y->mem > x->mem) - (y->mem < x->mem); if (!r) r = _wcsicmp(x->name, y->name); break;
    case 6: r = (y->io > x->io) - (y->io < x->io); if (!r) r = _wcsicmp(x->name, y->name); break;
    default: r = _wcsicmp(x->name, y->name); if (!r) r = x->kind - y->kind; return r;
    }
    return g_sortAsc ? r : -r;
}

static Item *NewItem(void)
{
    if (g_nitems == g_capitems) {
        int nc = g_capitems ? g_capitems * 2 : 256;
        Item *t = (Item *)realloc(g_items, (size_t)nc * sizeof(Item));
        if (!t) return NULL;
        g_items = t; g_capitems = nc;
    }
    memset(&g_items[g_nitems], 0, sizeof(Item));
    g_items[g_nitems].icon = -1;
    return &g_items[g_nitems++];
}

static Item *FindItem(int kind, const wchar_t *id)
{
    for (int i = 0; i < g_nitems; i++)
        if (g_items[i].kind == kind && _wcsicmp(g_items[i].id, id) == 0) return &g_items[i];
    return NULL;
}

static Item *SelectedItem(void)
{
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    return (sel >= 0 && sel < g_nview && g_view[sel] >= 0) ? &g_items[g_view[sel]] : NULL;
}

static const wchar_t *GroupName(int g)
{
    static const wchar_t *n[G_COUNT] = { L"Watch list", L"Apps", L"Background processes", L"Windows processes", L"Services" };
    return n[g];
}

static BOOL ItemVisible(const Item *it, const wchar_t *q)
{
    if (!it->watched) {
        if (!(it->kind == K_PROC ? g_showProc : g_showSvc)) return FALSE;
        if (g_onlyRun && !it->running) return FALSE;
    }
    return !q[0] || ContainsNoCase(it->name, q) || ContainsNoCase(it->detail, q) || ContainsNoCase(it->id, q);
}

/* The view lists group headers (entry < 0, value -1 - group) followed by that group's items (entry = index into g_items). */
static void RebuildView(void)
{
    wchar_t q[128];
    GetWindowTextW(g_search, q, 128);
    free(g_view);
    g_view = (int *)malloc((size_t)(g_nitems + G_COUNT + 1) * sizeof(int));
    g_nview = 0;
    ZeroMemory(g_groupCount, sizeof g_groupCount);
    for (int i = 0; i < g_nitems; i++) if (ItemVisible(&g_items[i], q)) g_groupCount[g_items[i].group]++;
    for (int g = 0; g < G_COUNT && g_view; g++) {
        if (!g_groupCount[g]) continue;
        g_view[g_nview++] = -1 - g;
        if (g_collapsed & (1u << g)) continue;
        for (int i = 0; i < g_nitems; i++)
            if (g_items[i].group == g && ItemVisible(&g_items[i], q)) g_view[g_nview++] = i;
    }
    ListView_SetItemCountEx(g_list, g_nview, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    InvalidateRect(g_list, NULL, TRUE);
}

static void ToggleGroup(int g)
{
    g_collapsed ^= 1u << g;
    SaveSettings();
    RebuildView();
}

static void UpdateButtons(void)
{
    const Item *it = SelectedItem();
    SetWindowTextW(g_bToggle, MonitorOn() ? L"⏸ Pause Monitoring" : L"▶ Start Monitoring");
    SetWindowTextW(g_bWatch, it && it->watched ? L"✔ Stop Watching" : L"☠ Kill & Watch");
    SetWindowTextW(g_bNotify, g_notify ? L"\U0001F514 Notifications: On" : L"\U0001F515 Notifications: Off");
    InvalidateRect(g_bToggle, NULL, FALSE); InvalidateRect(g_bWatch, NULL, FALSE); InvalidateRect(g_bNotify, NULL, FALSE);
}

static void RefreshStatus(void)
{
    int n; EnterCriticalSection(&g_cs); n = g_nrules; LeaveCriticalSection(&g_cs);
    MEMORYSTATUSEX ms; ms.dwLength = sizeof ms; if (!GlobalMemoryStatusEx(&ms)) ms.dwMemoryLoad = 0;
    swprintf(g_statusText, 300, L"Monitoring %ls   |   %d watched   |   %ld killed this session   |   CPU %.0f%%   |   Memory %lu%%",
             MonitorOn() ? L"ACTIVE" : L"PAUSED", n, (long)g_totalKills, g_sysCpu, (unsigned long)ms.dwMemoryLoad);
    InvalidateRect(g_status, NULL, TRUE);
    UpdateButtons();
    UpdateTray();
}

static BOOL ProcPath(DWORD pid, wchar_t *path)
{
    DWORD n = MAX_PATH; BOOL ok;
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) return FALSE;
    ok = QueryFullProcessImageNameW(p, 0, path, &n);
    CloseHandle(p);
    return ok;
}

static void AddServicesToList(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    BYTE *buf; DWORD need = 0, got = 0, cnt = 0, resume = 0; BOOL ok;
    if (!scm) return;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &need, &cnt, &resume, NULL);
    if (GetLastError() != ERROR_MORE_DATA || !need) { CloseServiceHandle(scm); return; }
    need += 8192;
    buf = (BYTE *)malloc(need);
    if (!buf) { CloseServiceHandle(scm); return; }
    resume = 0;
    do {
        ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf, need, &got, &cnt, &resume, NULL);
        if (!ok && GetLastError() != ERROR_MORE_DATA) break;
        const ENUM_SERVICE_STATUS_PROCESSW *s = (const ENUM_SERVICE_STATUS_PROCESSW *)buf;
        for (DWORD i = 0; i < cnt; i++) {
            Item *it = FindItem(K_SVC, s[i].lpServiceName);
            if (!it) { it = NewItem(); if (!it) break; it->kind = K_SVC; wcsncpy(it->id, s[i].lpServiceName, MAX_PATH - 1); }
            wcsncpy(it->name, s[i].lpDisplayName, MAX_PATH - 1);
            it->shared = (s[i].ServiceStatusProcess.dwServiceType & SERVICE_WIN32_SHARE_PROCESS) != 0;
            swprintf(it->detail, MAX_PATH, L"%ls%ls", it->id, it->shared ? L"  (shared process)" : L"");
            it->running = s[i].ServiceStatusProcess.dwCurrentState != SERVICE_STOPPED;
            it->havePath = TRUE;
            if ((s[i].ServiceStatusProcess.dwServiceType & SERVICE_WIN32_OWN_PROCESS) && s[i].ServiceStatusProcess.dwProcessId) {
                ProcStat *ps = FindStat(s[i].ServiceStatusProcess.dwProcessId);   /* shared svchost hosts are not split per service */
                if (ps) AddStats(it, ps);
            }
        }
    } while (!ok);
    free(buf);
    CloseServiceHandle(scm);
}

static DWORD g_winPids[2048]; static int g_nWinPids;

/* Collects the processes that own a window you could alt-tab to (the "Apps" of Task Manager). */
static BOOL CALLBACK EnumWinProc(HWND w, LPARAM l)
{
    DWORD pid = 0; int cloaked = 0; LONG ex; wchar_t cls[64];
    (void)l;
    if (!IsWindowVisible(w) || GetWindow(w, GW_OWNER)) return TRUE;
    ex = GetWindowLongW(w, GWL_EXSTYLE);
    if ((ex & WS_EX_TOOLWINDOW) && !(ex & WS_EX_APPWINDOW)) return TRUE;
    if (GetWindowTextLengthW(w) == 0) return TRUE;
    if (SUCCEEDED(DwmGetWindowAttribute(w, 14 /* DWMWA_CLOAKED */, &cloaked, sizeof cloaked)) && cloaked) return TRUE;
    GetClassNameW(w, cls, 64);
    if (wcscmp(cls, L"Progman") == 0 || wcscmp(cls, L"WorkerW") == 0) return TRUE;   /* the desktop itself */
    GetWindowThreadProcessId(w, &pid);
    if (pid && g_nWinPids < 2048) g_winPids[g_nWinPids++] = pid;
    return TRUE;
}

static BOOL PidHasWindow(DWORD pid)
{
    for (int i = 0; i < g_nWinPids; i++) if (g_winPids[i] == pid) return TRUE;
    return FALSE;
}

static void RefreshNow(void)
{
    int skind = -1; wchar_t sid[MAX_PATH]; HANDLE snap; const Item *cur = SelectedItem();
    sid[0] = 0;
    if (cur) { skind = cur->kind; wcscpy(sid, cur->id); }
    g_nitems = 0;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_nrules; i++) {
        Item *it = NewItem();
        if (!it) break;
        it->kind = g_rules[i].kind; wcscpy(it->id, g_rules[i].id); wcscpy(it->name, g_rules[i].label);
        wcscpy(it->detail, it->kind == K_PROC ? g_rules[i].path : g_rules[i].id);
        it->havePath = g_rules[i].path[0] != 0;
        it->watched = TRUE; it->kills = g_rules[i].kills; it->lastErr = g_rules[i].lastErr;
    }
    LeaveCriticalSection(&g_cs);
    g_nWinPids = 0;
    EnumWindows(EnumWinProc, 0);
    BeginSample();
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof pe;
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
            Item *it; wchar_t path[MAX_PATH];
            if (pe.th32ProcessID <= 4) continue;
            it = FindItem(K_PROC, pe.szExeFile);
            if (!it) { it = NewItem(); if (!it) break; it->kind = K_PROC; wcsncpy(it->id, pe.szExeFile, MAX_PATH - 1); wcscpy(it->name, it->id); }
            it->running = TRUE; it->count++;
            { ProcStat *ps = SampleProc(pe.th32ProcessID); if (ps) AddStats(it, ps); }
            if (PidHasWindow(pe.th32ProcessID)) it->hasWin = TRUE;
            if (!it->havePath && ProcPath(pe.th32ProcessID, path)) { wcscpy(it->detail, path); it->havePath = TRUE; }
        }
        CloseHandle(snap);
    }
    PruneStats();
    AddServicesToList();
    for (int i = 0; i < g_nitems; i++) {
        Item *it = &g_items[i];
        it->system = it->kind == K_PROC && g_winDir[0] && _wcsnicmp(it->detail, g_winDir, wcslen(g_winDir)) == 0;
        it->group = it->watched ? G_WATCH : it->kind == K_SVC ? G_SVC : it->hasWin ? G_APPS : (it->system || !it->havePath) ? G_WIN : G_BG;
    }
    qsort(g_items, (size_t)g_nitems, sizeof(Item), ItemCmp);
    RebuildView();
    ListView_SetItemState(g_list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (skind >= 0)
        for (int i = 0; i < g_nview; i++)
            if (g_view[i] >= 0 && g_items[g_view[i]].kind == skind && _wcsicmp(g_items[g_view[i]].id, sid) == 0) {
                ListView_SetItemState(g_list, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                break;
            }
    RefreshStatus();
}

/* While the window is hidden (tray) or minimized nobody sees the list, so skip the scan. */
static BOOL WindowIdle(void) { return !g_hwnd || !IsWindowVisible(g_hwnd) || IsIconic(g_hwnd); }

static void RefreshApps(void)
{
    if (WindowIdle()) { g_refreshPending = TRUE; RefreshStatus(); return; }
    g_refreshPending = FALSE;
    RefreshNow();
}

static void TrimMemory(void) { SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1); }

/* ------------------------------------------------------------------ */
/* Actions                                                             */
/* ------------------------------------------------------------------ */
/* FALSE (with an explanation) if this item must never be killed, or the user backed out. */
static BOOL ConfirmKill(const Item *it, const wchar_t *verb)
{
    wchar_t m[600];
    if (it->kind == K_PROC ? IsProtectedProc(it->id) : IsProtectedSvc(it->id)) {
        swprintf(m, 600, L"%ls is a critical Windows component (or this program itself) and is protected. Killing it could crash or lock the system, so it is not allowed.", it->name);
        ShowDialog(g_hwnd, APP_NAME, m, L"OK", NULL, NULL);
        return FALSE;
    }
    if (it->system) {
        swprintf(m, 600, L"%ls lives in the Windows folder. Killing a Windows component can make parts of the system stop working.\n\n%ls it anyway?", it->name, verb);
        return ShowDialog(g_hwnd, APP_NAME, m, verb, L"Cancel", NULL) == 1;
    }
    return TRUE;
}

static void WatchItem(const Item *it)
{
    wchar_t id[MAX_PATH], label[MAX_PATH], path[MAX_PATH]; int kind = it->kind;
    if (!ConfirmKill(it, L"Kill & Watch")) return;
    wcscpy(id, it->id); wcscpy(label, it->name); wcscpy(path, kind == K_PROC && it->havePath ? it->detail : L"");
    AddRule(kind, id, label, path);
    QueueOnce(kind, id, path);    /* kill right now, even while monitoring is paused */
    RefreshApps();
}

static void UnwatchItem(const Item *it)
{
    wchar_t id[MAX_PATH]; int kind = it->kind;
    wcscpy(id, it->id);
    RemoveRule(kind, id);
    RefreshApps();
}

static void KillOnce(const Item *it)
{
    wchar_t id[MAX_PATH]; int kind = it->kind;
    if (!ConfirmKill(it, L"Kill")) return;
    wcscpy(id, it->id);
    QueueOnce(kind, id, kind == K_PROC && it->havePath ? it->detail : L"");
}

static void ToggleSelected(void)
{
    const Item *it = SelectedItem();
    if (!it) return;
    if (it->watched) UnwatchItem(it); else WatchItem(it);
}

static void AddProgram(void)
{
    wchar_t file[MAX_PATH] = L""; OPENFILENAMEW ofn; Item tmp;
    ZeroMemory(&ofn, sizeof ofn);
    ofn.lStructSize = sizeof ofn; ofn.hwndOwner = g_hwnd; ofn.lpstrFile = file; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Programs (*.exe)\0*.exe\0All files\0*.*\0";
    ofn.lpstrTitle = L"Choose a program to keep closed";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return;
    ZeroMemory(&tmp, sizeof tmp);
    tmp.kind = K_PROC; wcscpy(tmp.id, BaseName(file)); wcscpy(tmp.name, tmp.id); wcscpy(tmp.detail, file); tmp.havePath = TRUE;
    tmp.system = g_winDir[0] && _wcsnicmp(file, g_winDir, wcslen(g_winDir)) == 0;
    WatchItem(&tmp);
}

static void ToggleMonitor(void)
{
    LONG now = InterlockedCompareExchange(&g_paused, 0, 0) ? 0 : 1;
    InterlockedExchange(&g_paused, now);
    Log(L"Monitoring %ls", now ? L"paused" : L"started");
    if (!now) SetEvent(g_evKick);
    RefreshApps();
    InvalidateRect(g_list, NULL, FALSE);
}

static void CopyToClipboard(HWND owner, const wchar_t *text)
{
    size_t n = (wcslen(text) + 1) * sizeof(wchar_t); HGLOBAL g;
    if (!OpenClipboard(owner)) return;
    EmptyClipboard();
    g = GlobalAlloc(GMEM_MOVEABLE, n);
    if (g) { memcpy(GlobalLock(g), text, n); GlobalUnlock(g); if (!SetClipboardData(CF_UNICODETEXT, g)) GlobalFree(g); }
    CloseClipboard();
}

static void OpenLocation(const Item *it)
{
    wchar_t arg[MAX_PATH + 16];
    if (it->kind != K_PROC || !it->havePath) return;
    swprintf(arg, MAX_PATH + 16, L"/select,\"%ls\"", it->detail);
    ShellExecuteW(g_hwnd, L"open", L"explorer.exe", arg, NULL, SW_SHOWNORMAL);
}

/* ------------------------------------------------------------------ */
/* Row drawing                                                         */
/* ------------------------------------------------------------------ */
static COLORREF Blend(COLORREF a, COLORREF b, int pct)
{
    return RGB(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * pct / 100,
               GetGValue(a) + (GetGValue(b) - GetGValue(a)) * pct / 100,
               GetBValue(a) + (GetBValue(b) - GetBValue(a)) * pct / 100);
}

static BOOL RowColor(const Item *it, COLORREF *out)
{
    if ((g_hl & HL_WATCHED) && it->watched) { *out = g_dark ? RGB(86, 40, 46) : RGB(252, 212, 212); return TRUE; }
    if ((g_hl & HL_SYSTEM) && it->system) { *out = g_dark ? RGB(32, 50, 84) : RGB(206, 222, 250); return TRUE; }
    return FALSE;
}

static int IconFor(Item *it)
{
    if (it->icon < 0) {
        SHFILEINFOW fi; DWORD flags = SHGFI_SYSICONINDEX | SHGFI_SMALLICON; wchar_t svcPath[MAX_PATH];
        const wchar_t *p = it->detail;
        ZeroMemory(&fi, sizeof fi);
        if (it->kind == K_SVC) {
            if (g_svcIcon >= 0) { it->icon = g_svcIcon; return it->icon; }
            swprintf(svcPath, MAX_PATH, L"%ls\\System32\\services.exe", g_winDir); p = svcPath;
        } else if (!it->havePath) { p = it->name; flags |= SHGFI_USEFILEATTRIBUTES; }
        else if (GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES) flags |= SHGFI_USEFILEATTRIBUTES;
        SHGetFileInfoW(p, FILE_ATTRIBUTE_NORMAL, &fi, sizeof fi, flags);
        it->icon = fi.iIcon;
        if (it->kind == K_SVC) g_svcIcon = fi.iIcon;
    }
    return it->icon;
}

static const wchar_t *StatusText(const Item *it)
{
    static wchar_t buf[4][96]; static int k;
    wchar_t *o = buf[k++ & 3]; size_t n;
    if (it->watched) {
        n = (size_t)swprintf(o, 96, L"%ls", MonitorOn() ? L"● Auto-kill" : L"● Watching (paused)");
        if (it->running && !MonitorOn()) n += (size_t)swprintf(o + n, 96 - n, L" · running");
        if (it->kills) n += (size_t)swprintf(o + n, 96 - n, L" · %u killed", it->kills);
        if (it->lastErr) swprintf(o + n, 96 - n, it->lastErr == ERROR_ACCESS_DENIED ? L" · access denied" : L" · failed (error %lu)", (unsigned long)it->lastErr);
        return o;
    }
    if (it->running) {
        if (it->kind == K_PROC && it->count > 1) swprintf(o, 96, L"● Running (%d)", it->count);
        else return L"● Running";
        return o;
    }
    return it->kind == K_SVC ? L"○ Stopped" : L"○ Not running";
}

/* Group title row: chevron, bold name and the number of items, like Task Manager. */
static void DrawGroupHeader(const DRAWITEMSTRUCT *di, int g)
{
    HDC dc = di->hDC; RECT r = di->rcItem; wchar_t t[96]; UINT dpi = GetDpiForWindow(g_list); int pad = MulDiv(10, (int)dpi, 96);
    HBRUSH b = CreateSolidBrush(cBg); HPEN pen = CreatePen(PS_SOLID, 1, cLine); HGDIOBJ of, op;
    FillRect(dc, &r, b); DeleteObject(b);
    op = SelectObject(dc, pen);
    MoveToEx(dc, r.left, r.bottom - 1, NULL); LineTo(dc, r.right, r.bottom - 1);
    SelectObject(dc, op); DeleteObject(pen);
    of = SelectObject(dc, g_fontBold);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, g == G_WATCH ? cRed : cText);
    r.left += pad;
    swprintf(t, 96, L"%ls  %ls (%d)", (g_collapsed & (1u << g)) ? L"▸" : L"▾", GroupName(g), g_groupCount[g]);
    DrawTextW(dc, t, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
    SelectObject(dc, of);
}

static void DrawListRow(const DRAWITEMSTRUCT *di)
{
    HDC dc = di->hDC; int i = (int)di->itemID; RECT row = di->rcItem; COLORREF bg = cBg, hc;
    BOOL sel = (di->itemState & ODS_SELECTED) != 0;
    HWND hdr = ListView_GetHeader(g_list);
    HGDIOBJ of;
    UINT dpi = GetDpiForWindow(g_list);
    Item *it;
    if (i < 0 || i >= g_nview) return;
    if (g_view[i] < 0) { DrawGroupHeader(di, -1 - g_view[i]); return; }
    it = &g_items[g_view[i]];
    if (sel) bg = g_dark ? RGB(48, 68, 108) : RGB(186, 208, 245);
    else if (RowColor(it, &hc)) bg = hc;
    if (i == g_hotRow) bg = Blend(bg, g_dark ? RGB(255, 255, 255) : RGB(0, 0, 0), sel ? 6 : 11);
    { HBRUSH b = CreateSolidBrush(bg); FillRect(dc, &row, b); DeleteObject(b); }
    of = SelectObject(dc, g_font);
    SetBkMode(dc, TRANSPARENT);
    for (int c = 0; c < 7; c++) {
        RECT hr, cell; const wchar_t *txt; COLORREF col = cText; int pad = MulDiv(6, (int)dpi, 96); UINT fl = DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS | DT_NOPREFIX;
        if (!Header_GetItemRect(hdr, c, &hr)) continue;
        cell = row; cell.left = hr.left; cell.right = hr.right;
        SaveDC(dc);
        IntersectClipRect(dc, cell.left, cell.top, cell.right, cell.bottom);
        cell.left += pad; cell.right -= pad;
        if (c == 0) {
            int ic = MulDiv(16, (int)dpi, 96);
            if (g_sysIL) ImageList_DrawEx(g_sysIL, IconFor(it), dc, cell.left, cell.top + (cell.bottom - cell.top - ic) / 2, ic, ic, CLR_NONE, CLR_NONE, ILD_TRANSPARENT);
            cell.left += ic + pad;
            txt = it->name;
            if (!it->running && !it->watched) col = cDim;
        } else if (c == 1) { txt = it->detail; col = cDim; }
        else if (c == 2) { txt = it->kind == K_SVC ? L"Service" : L"Process"; col = cDim; }
        else if (c == 3) { txt = StatusText(it); col = it->watched ? cRed : (it->running ? cGreen : cDim); }
        else {
            int heat = sel ? 0 : HeatPct(c, it);
            if (heat) { RECT tr = {hr.left, row.top, hr.right, row.bottom}; HBRUSH hb = CreateSolidBrush(Blend(bg, g_dark ? RGB(30, 110, 230) : RGB(70, 150, 240), heat)); FillRect(dc, &tr, hb); DeleteObject(hb); }
            txt = CellText(it, c); fl = DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_NOPREFIX;
        }
        SetTextColor(dc, col);
        DrawTextW(dc, txt, -1, &cell, fl);
        RestoreDC(dc, -1);
    }
    SelectObject(dc, of);
}

static void ShowRowMenu(int row)
{
    const Item *it = &g_items[g_view[row]];
    HMENU m = CreatePopupMenu(); POINT pt;
    AppendMenuW(m, MF_STRING | MF_DISABLED, 0, it->name);
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    if (it->watched) AppendMenuW(m, MF_STRING, IDM_ROW_UNWATCH, L"Stop watching");
    else AppendMenuW(m, MF_STRING, IDM_ROW_WATCH, L"Kill && watch (kill again whenever it starts)");
    AppendMenuW(m, MF_STRING | ((it->running || it->watched) ? 0 : MF_GRAYED), IDM_ROW_KILL, L"Kill once");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | ((it->kind == K_PROC && it->havePath) ? 0 : MF_GRAYED), IDM_LOCATION, L"Open file location");
    AppendMenuW(m, MF_STRING, IDM_COPYNAME, L"Copy name");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_REFRESH, L"Refresh list\tF5");
    GetCursorPos(&pt);
    g_menuOpen = TRUE;
    TrackPopupMenu(m, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hwnd, NULL);
    g_menuOpen = FALSE;
    DestroyMenu(m);
}

static LRESULT OnNotify(NMHDR *nh)
{
    if (nh->hwndFrom != g_list) return 0;
    switch (nh->code) {
    case LVN_GETDISPINFOW: {
        NMLVDISPINFOW *d = (NMLVDISPINFOW *)nh;
        if (d->item.iItem >= 0 && d->item.iItem < g_nview && g_view[d->item.iItem] >= 0) {
            Item *it = &g_items[g_view[d->item.iItem]];
            if ((d->item.mask & LVIF_IMAGE) && d->item.iSubItem == 0) d->item.iImage = IconFor(it);
            if (d->item.mask & LVIF_TEXT) {
                switch (d->item.iSubItem) {
                case 0: d->item.pszText = (LPWSTR)it->name; break;
                case 1: d->item.pszText = (LPWSTR)it->detail; break;
                case 2: d->item.pszText = (LPWSTR)(it->kind == K_SVC ? L"Service" : L"Process"); break;
                case 3: d->item.pszText = (LPWSTR)StatusText(it); break;
                default: d->item.pszText = (LPWSTR)CellText(it, d->item.iSubItem); break;
                }
            }
        }
        return 0;
    }
    case LVN_COLUMNCLICK: {
        int c = ((NMLISTVIEW *)nh)->iSubItem;
        /* click cycle: ascending -> descending -> default order */
        if (g_sortCol == c) { if (g_sortAsc) g_sortAsc = FALSE; else { g_sortCol = -1; g_sortAsc = TRUE; } }
        else { g_sortCol = c; g_sortAsc = TRUE; }
        RefreshNow();
        InvalidateRect(ListView_GetHeader(g_list), NULL, TRUE);
        return 0;
    }
    case LVN_ITEMCHANGED:
        if (((NMLISTVIEW *)nh)->uChanged & LVIF_STATE) UpdateButtons();
        return 0;
    case NM_RCLICK: {
        NMITEMACTIVATE *ia = (NMITEMACTIVATE *)nh; LVHITTESTINFO ht; int i = ia->iItem;
        if (i < 0) { ZeroMemory(&ht, sizeof ht); ht.pt = ia->ptAction; i = ListView_HitTest(g_list, &ht); }
        if (i >= 0 && i < g_nview && g_view[i] >= 0) {
            ListView_SetItemState(g_list, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ShowRowMenu(i);
        }
        return 0;
    }
    case NM_CLICK: case NM_DBLCLK: {
        NMITEMACTIVATE *ia = (NMITEMACTIVATE *)nh; LVHITTESTINFO ht; int i = ia->iItem;
        if (i < 0) { ZeroMemory(&ht, sizeof ht); ht.pt = ia->ptAction; i = ListView_HitTest(g_list, &ht); }
        if (i >= 0 && i < g_nview && g_view[i] < 0) ToggleGroup(-1 - g_view[i]);          /* click on a group title: collapse / expand */
        else if (nh->code == NM_DBLCLK) ToggleSelected();
        return 0;
    }
    case LVN_KEYDOWN:
        if (((NMLVKEYDOWN *)nh)->wVKey == VK_SPACE || ((NMLVKEYDOWN *)nh)->wVKey == VK_RETURN) {
            int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < g_nview && g_view[sel] < 0) { int g = -1 - g_view[sel]; ToggleGroup(g); }
            else if (((NMLVKEYDOWN *)nh)->wVKey == VK_SPACE) ToggleSelected();
        }
        return 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main window                                                         */
/* ------------------------------------------------------------------ */
static BOOL SystemUsesDark(void)
{
    DWORD v = 1, sz = sizeof v;
    RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUseLightTheme",
                 RRF_RT_REG_DWORD, NULL, &v, &sz);
    return v == 0;
}

static HWND g_logList;

/* Make popup/context menus follow the app theme (undocumented uxtheme ordinals 135 and 136). */
static void ThemeMenus(BOOL dark)
{
    typedef int (WINAPI *PFN_SPAM)(int);
    typedef void (WINAPI *PFN_FLUSH)(void);
    HMODULE ux = LoadLibraryW(L"uxtheme.dll");
    if (!ux) return;
    PFN_SPAM spam = (PFN_SPAM)(void *)GetProcAddress(ux, MAKEINTRESOURCEA(135));
    PFN_FLUSH flush = (PFN_FLUSH)(void *)GetProcAddress(ux, MAKEINTRESOURCEA(136));
    if (spam) spam(dark ? 2 : 3);   /* ForceDark / ForceLight */
    if (flush) flush();
}

static void ApplyTheme(void)
{
    BOOL dark;
    g_dark = (g_theme == 0) || (g_theme == 2 && SystemUsesDark());
    if (g_dark) {
        cBg = RGB(30, 30, 34); cPanel = RGB(40, 40, 46); cText = RGB(228, 228, 232); cDim = RGB(150, 150, 160);
        cGreen = RGB(110, 214, 140); cRed = RGB(240, 110, 110); cLine = RGB(70, 70, 78); cAmber = RGB(244, 190, 90);
    } else {
        cBg = RGB(251, 251, 253); cPanel = RGB(236, 236, 242); cText = RGB(28, 28, 32); cDim = RGB(105, 105, 118);
        cGreen = RGB(20, 128, 60); cRed = RGB(200, 40, 40); cLine = RGB(200, 200, 210); cAmber = RGB(176, 96, 0);
    }
    if (g_bgBrush) DeleteObject(g_bgBrush);
    if (g_editBrush) DeleteObject(g_editBrush);
    ThemeMenus(g_dark);
    g_bgBrush = CreateSolidBrush(cBg);
    g_editBrush = CreateSolidBrush(cPanel);
    if (!g_hwnd) return;
    dark = g_dark;
    DwmSetWindowAttribute(g_hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof dark);
    ThemeCtl(g_list);
    ListView_SetBkColor(g_list, cBg); ListView_SetTextBkColor(g_list, CLR_NONE); ListView_SetTextColor(g_list, cText);
    if (g_histWnd) {
        DwmSetWindowAttribute(g_histWnd, 20, &dark, sizeof dark);
        ThemeCtl(g_histList);
        SetWindowTheme(g_histEdit, g_dark ? L"DarkMode_CFD" : L"CFD", NULL);
        ListView_SetBkColor(g_histList, cBg); ListView_SetTextBkColor(g_histList, cBg); ListView_SetTextColor(g_histList, cText);
        RedrawWindow(g_histWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME);
    }
    if (g_logWnd) {
        DwmSetWindowAttribute(g_logWnd, 20, &dark, sizeof dark);
        ThemeCtl(g_logList);
        ListView_SetBkColor(g_logList, cBg); ListView_SetTextBkColor(g_logList, cBg); ListView_SetTextColor(g_logList, cText);
        RedrawWindow(g_logWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME);
    }
    RedrawWindow(g_hwnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME | RDW_UPDATENOW);
}

static int BtnTextW(const wchar_t *t)
{
    HDC dc = GetDC(g_hwnd); HGDIOBJ of = SelectObject(dc, g_font); SIZE sz;
    GetTextExtentPoint32W(dc, t, (int)wcslen(t), &sz);
    SelectObject(dc, of); ReleaseDC(g_hwnd, dc);
    return sz.cx;
}

static void Layout(void)
{
    RECT rc; GetClientRect(g_hwnd, &rc);
    int W = rc.right, H = rc.bottom;
    UINT dpi = GetDpiForWindow(g_hwnd);
    #define S(v) MulDiv((v), (int)dpi, 96)
    int pad = S(10), bh = S(32), y = S(10), x = pad, gap = S(8), padw = S(40);
    #define TW(t) BtnTextW(t)
    int wT = max(TW(L"\u23F8 Pause Monitoring"), TW(L"\u25B6 Start Monitoring")) + padw;
    int wW = max(TW(L"\u2620 Kill & Watch"), TW(L"\u2714 Stop Watching")) + padw;
    int wK = TW(L"\u2716 Kill Once") + padw;
    int wAdd = TW(L"\u2795 Add Program...") + padw;
    int wN = max(TW(L"\U0001F514 Notifications: On"), TW(L"\U0001F515 Notifications: Off")) + padw;
    int wO = TW(L"\u2699 Options") + padw;
    #undef TW
    MoveWindow(g_bToggle, x, y, wT, bh, TRUE); x += wT + gap;
    MoveWindow(g_bWatch, x, y, wW, bh, TRUE); x += wW + gap;
    MoveWindow(g_bKill, x, y, wK, bh, TRUE); x += wK + gap;
    MoveWindow(g_bAdd, x, y, wAdd, bh, TRUE); x += wAdd + gap;
    MoveWindow(g_bNotify, x, y, wN, bh, TRUE); x += wN + gap;
    MoveWindow(g_bOptions, x, y, wO, bh, TRUE); x += wO + gap;
    g_sepX = x - gap / 2; g_sepY0 = y + S(6); g_sepY1 = y + bh - S(6);
    int sw = W - x - pad; if (sw < S(120)) sw = S(120);
    {
        TEXTMETRICW tm; HDC dc = GetDC(g_hwnd); HGDIOBJ of = SelectObject(dc, g_font);
        GetTextMetricsW(dc, &tm); SelectObject(dc, of); ReleaseDC(g_hwnd, dc);
        SetRect(&g_searchBox, x, y, x + sw, y + bh);
        MoveWindow(g_search, x + S(14), y + (bh - tm.tmHeight) / 2, sw - S(28), tm.tmHeight, TRUE);
    }
    int top = y + bh + S(10), sh = S(26);
    MoveWindow(g_list, 0, top, W, H - top - sh, TRUE);
    MoveWindow(g_status, 0, H - sh, W, sh, TRUE);
    ListView_SetColumnWidth(g_list, 0, S(240));
    ListView_SetColumnWidth(g_list, 2, S(75));
    ListView_SetColumnWidth(g_list, 3, S(190));
    ListView_SetColumnWidth(g_list, 4, S(75));
    ListView_SetColumnWidth(g_list, 5, S(105));
    ListView_SetColumnWidth(g_list, 6, S(105));
    ListView_SetColumnWidth(g_list, 1, W - S(240) - S(75) - S(190) - S(75) - S(105) - S(105) - GetSystemMetrics(SM_CXVSCROLL) - 4);
    #undef S
}

/* Hover highlight: remember which row the pointer is over and repaint just that row. */
static void SetHotRow(int row)
{
    RECT r; int old = g_hotRow;
    if (row == old) return;
    g_hotRow = row;
    if (old >= 0 && ListView_GetItemRect(g_list, old, &r, LVIR_BOUNDS)) InvalidateRect(g_list, &r, FALSE);
    if (row >= 0 && ListView_GetItemRect(g_list, row, &r, LVIR_BOUNDS)) InvalidateRect(g_list, &r, FALSE);
}

static void UpdateHotFromCursor(HWND h)
{
    POINT p; LVHITTESTINFO ht;
    GetCursorPos(&p); ScreenToClient(h, &p);
    ZeroMemory(&ht, sizeof ht); ht.pt = p;
    SetHotRow(ListView_HitTest(h, &ht) >= 0 ? ht.iItem : -1);
}

static LRESULT CALLBACK ListHoverProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    LRESULT r;
    (void)id; (void)ref;
    switch (m) {
    case WM_MOUSEMOVE:
        if (!GetPropW(h, L"hov")) { TRACKMOUSEEVENT t = {sizeof t, TME_LEAVE, h, 0}; SetPropW(h, L"hov", (HANDLE)1); TrackMouseEvent(&t); }
        UpdateHotFromCursor(h);
        break;
    case WM_MOUSELEAVE:
        RemovePropW(h, L"hov"); SetHotRow(-1);
        break;
    case WM_MOUSEWHEEL: case WM_VSCROLL:
        r = DefSubclassProc(h, m, w, l);
        UpdateHotFromCursor(h);
        return r;
    case WM_NCDESTROY:
        RemovePropW(h, L"hov"); RemoveWindowSubclass(h, ListHoverProc, 2);
        break;
    }
    return DefSubclassProc(h, m, w, l);
}

static LRESULT CALLBACK HeaderProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)id; (void)ref;
    if (m == WM_ERASEBKGND) return 1;
    if (m == WM_PAINT) {
        PAINTSTRUCT ps; RECT rc;
        HDC dc = BeginPaint(h, &ps);
        int n = Header_GetItemCount(h);
        UINT_PTR ralign = (UINT_PTR)GetPropW(h, L"ralign"); BOOL nosort = GetPropW(h, L"nosort") != NULL, ownsort = GetPropW(h, L"ownsort") != NULL;   /* set by the owner of the list */
        HBRUSH bg = CreateSolidBrush(COL_PANEL);
        HPEN pen = CreatePen(PS_SOLID, 1, COL_LINE);
        HGDIOBJ oldFont = SelectObject(dc, g_font), oldPen = SelectObject(dc, pen);
        GetClientRect(h, &rc);
        FillRect(dc, &rc, bg);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, COL_TEXT);
        for (int i = 0; i < n; i++) {
            RECT r; wchar_t t[64]; HDITEMW hi;
            Header_GetItemRect(h, i, &r);
            ZeroMemory(&hi, sizeof hi);
            hi.mask = HDI_TEXT; hi.pszText = t; hi.cchTextMax = 48; t[0] = 0;
            Header_GetItem(h, i, &hi);
            MoveToEx(dc, r.right - 1, r.top + 4, NULL); LineTo(dc, r.right - 1, r.bottom - 4);
            if (ownsort) { if (i == (int)(INT_PTR)GetPropW(h, L"scol") - 1) wcscat(t, GetPropW(h, L"sasc") ? L"  \u25B2" : L"  \u25BC"); }
            else if (i == g_sortCol && !nosort) wcscat(t, g_sortAsc ? L"  \u25B2" : L"  \u25BC");
            r.left += 8; r.right -= 8;
            DrawTextW(dc, t, -1, &r, DT_SINGLELINE | DT_VCENTER | (((ralign >> i) & 1) ? DT_RIGHT : DT_LEFT) | DT_END_ELLIPSIS);
        }
        SelectObject(dc, oldPen); SelectObject(dc, oldFont);
        DeleteObject(pen); DeleteObject(bg);
        EndPaint(h, &ps);
        return 0;
    }
    return DefSubclassProc(h, m, w, l);
}

static void CreateFonts(UINT dpi)
{
    NONCLIENTMETRICSW ncm; LOGFONTW lf;
    ZeroMemory(&ncm, sizeof ncm); ncm.cbSize = sizeof ncm;
    SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0, dpi);
    if (g_font) DeleteObject(g_font);
    if (g_fontBold) DeleteObject(g_fontBold);
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    lf = ncm.lfMessageFont; lf.lfWeight = FW_SEMIBOLD;
    g_fontBold = CreateFontIndirectW(&lf);
}

static HWND MakeChild(HWND parent, const wchar_t *cls, const wchar_t *text, DWORD style, int x, int y, int w, int h, int id)
{
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    return c;
}

static void CreateControls(HWND hwnd)
{
    LVCOLUMNW col;
    CreateFonts(GetDpiForWindow(hwnd));

    g_bToggle = MakeChild(hwnd, L"BUTTON", L"Monitoring", BS_OWNERDRAW, 0, 0, 10, 10, IDC_TOGGLE);
    g_bWatch = MakeChild(hwnd, L"BUTTON", L"Kill & Watch", BS_OWNERDRAW, 0, 0, 10, 10, IDC_WATCH);
    g_bKill = MakeChild(hwnd, L"BUTTON", L"\u2716 Kill Once", BS_OWNERDRAW, 0, 0, 10, 10, IDC_KILL);
    g_bAdd = MakeChild(hwnd, L"BUTTON", L"\u2795 Add Program...", BS_OWNERDRAW, 0, 0, 10, 10, IDC_ADD);
    g_bNotify = MakeChild(hwnd, L"BUTTON", L"Notifications", BS_OWNERDRAW, 0, 0, 10, 10, IDC_NOTIFY);
    g_bOptions = MakeChild(hwnd, L"BUTTON", L"\u2699 Options", BS_OWNERDRAW, 0, 0, 10, 10, IDC_OPTIONS);
    FlatButton(g_bToggle); FlatButton(g_bWatch); FlatButton(g_bKill); FlatButton(g_bAdd); FlatButton(g_bNotify); FlatButton(g_bOptions);

    g_search = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 10, 10, hwnd, (HMENU)IDC_SEARCH, g_inst, NULL);
    SendMessageW(g_search, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g_search, EM_SETCUEBANNER, TRUE, (LPARAM)L"\U0001F50D Search processes and services...");

    g_list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA | LVS_SHAREIMAGELISTS | LVS_OWNERDRAWFIXED,
                             0, 0, 10, 10, hwnd, (HMENU)IDC_LIST, g_inst, NULL);
    SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    ListView_SetBkColor(g_list, COL_BG);
    ListView_SetTextBkColor(g_list, CLR_NONE);
    ListView_SetTextColor(g_list, COL_TEXT);
    ThemeCtl(g_list);
    SetWindowSubclass(ListView_GetHeader(g_list), HeaderProc, 1, 0);
    SetPropW(ListView_GetHeader(g_list), L"ralign", (HANDLE)(UINT_PTR)0x70);   /* CPU, Memory, Disk */
    SetWindowSubclass(g_list, ListHoverProc, 2, 0);
    {
        SHFILEINFOW fi; ZeroMemory(&fi, sizeof fi);
        HIMAGELIST il = (HIMAGELIST)SHGetFileInfoW(L"C:\\Windows\\explorer.exe", 0, &fi, sizeof fi, SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
        if (il) { ListView_SetImageList(g_list, il, LVSIL_SMALL); g_sysIL = il; }
    }
    ZeroMemory(&col, sizeof col);
    col.mask = LVCF_TEXT | LVCF_WIDTH; col.cx = 200;
    col.pszText = L"Name"; ListView_InsertColumn(g_list, 0, &col);
    col.pszText = L"Path / Service name"; ListView_InsertColumn(g_list, 1, &col);
    col.pszText = L"Type"; ListView_InsertColumn(g_list, 2, &col);
    col.pszText = L"Status"; ListView_InsertColumn(g_list, 3, &col);
    col.pszText = L"CPU"; ListView_InsertColumn(g_list, 4, &col);
    col.pszText = L"Memory"; ListView_InsertColumn(g_list, 5, &col);
    col.pszText = L"Disk"; ListView_InsertColumn(g_list, 6, &col);

    g_status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 10, 10, hwnd, (HMENU)IDC_STATUS, g_inst, NULL);
    SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
}

/* ---------- notification area ---------- */
static void ShowMain(void)
{
    ShowWindow(g_hwnd, g_wantMax ? SW_SHOWMAXIMIZED : SW_SHOW);
    g_wantMax = FALSE;
    if (IsIconic(g_hwnd)) ShowWindow(g_hwnd, SW_RESTORE);
    SetForegroundWindow(g_hwnd);
}

static void AddTray(void)
{
    ZeroMemory(&g_nid, sizeof g_nid);
    g_nid.cbSize = sizeof g_nid; g_nid.hWnd = g_hwnd; g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY; g_nid.hIcon = g_iconSmall;
    wcscpy(g_nid.szTip, APP_NAME);
    g_trayOk = Shell_NotifyIconW(NIM_ADD, &g_nid);
    if (!g_trayOk && g_hwnd) SetTimer(g_hwnd, TIMER_TRAY, 3000, NULL);   /* at logon the taskbar may not exist yet */
    else if (g_hwnd) KillTimer(g_hwnd, TIMER_TRAY);
}

static void UpdateTray(void)
{
    int n;
    if (!g_nid.hWnd) return;
    EnterCriticalSection(&g_cs); n = g_nrules; LeaveCriticalSection(&g_cs);
    swprintf(g_nid.szTip, 128, L"%ls\n%ls - %d watched", APP_NAME, MonitorOn() ? L"Monitoring ON" : L"Monitoring PAUSED", n);
    g_nid.hIcon = g_iconSmall;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void Balloon(const wchar_t *text)
{
    NOTIFYICONDATAW n;
    if (!g_trayOk) return;
    n = g_nid; n.uFlags = NIF_INFO; n.dwInfoFlags = NIIF_INFO | NIIF_NOSOUND;
    wcsncpy(n.szInfoTitle, APP_NAME, 63); n.szInfoTitle[63] = 0;
    wcsncpy(n.szInfo, text, 255); n.szInfo[255] = 0;
    Shell_NotifyIconW(NIM_MODIFY, &n);
}

static void SaveWindowPos(void)
{
    WINDOWPLACEMENT wp; wchar_t n[16];
    if (!g_hwnd) return;
    wp.length = sizeof wp;
    if (!GetWindowPlacement(g_hwnd, &wp)) return;
    #define PUT(key, val) swprintf(n, 16, L"%ld", (long)(val)); WritePrivateProfileStringW(L"window", key, n, g_iniFile)
    PUT(L"x", wp.rcNormalPosition.left);
    PUT(L"y", wp.rcNormalPosition.top);
    PUT(L"w", wp.rcNormalPosition.right - wp.rcNormalPosition.left);
    PUT(L"h", wp.rcNormalPosition.bottom - wp.rcNormalPosition.top);
    PUT(L"max", wp.showCmd == SW_SHOWMAXIMIZED || (wp.flags & WPF_RESTORETOMAXIMIZED) ? 1 : 0);
    #undef PUT
}

static void QuitApp(void)
{
    Log(L"Quit requested");
    SaveWindowPos();
    g_quit = TRUE;
    DestroyWindow(g_hwnd);
}

static HMENU BuildOptionsMenu(void);

static void ShowTrayMenu(void)
{
    POINT pt; GetCursorPos(&pt);
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, IDT_SHOW, L"Show/Hide");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (MonitorOn() ? MF_CHECKED : 0), IDT_MONITOR, L"Monitoring");
    AppendMenuW(m, MF_STRING | (g_notify ? MF_CHECKED : 0), IDT_NOTIFY, L"Notifications");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_POPUP, (UINT_PTR)BuildOptionsMenu(), L"Options");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDT_EXIT, L"Exit");
    SetForegroundWindow(g_hwnd);
    g_menuOpen = TRUE;
    TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_hwnd, NULL);
    g_menuOpen = FALSE;
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

/* ---------- start with Windows (scheduled task: runs elevated, no UAC prompt) ---------- */
#define TASK_NAME L"SailHighSeaWinProcessKiller"

static DWORD RunHidden(const wchar_t *cmd)
{
    wchar_t buf[2048]; STARTUPINFOW si; PROCESS_INFORMATION pi; DWORD code = 1;
    wcsncpy(buf, cmd, 2047); buf[2047] = 0;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 1;
    WaitForSingleObject(pi.hProcess, 15000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code;
}

static BOOL AutostartEnabled(void) { g_autoCache = RunHidden(L"schtasks.exe /query /tn " TASK_NAME) == 0; return g_autoCache; }

static BOOL RunCapture(const wchar_t *cmd, wchar_t *out, int cap)
{
    wchar_t buf[1024]; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; HANDLE rd = NULL, wr = NULL; STARTUPINFOW si; PROCESS_INFORMATION pi;
    char raw[8192]; DWORD got, total = 0; BOOL ok = FALSE;
    out[0] = 0; wcsncpy(buf, cmd, 1023); buf[1023] = 0;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return FALSE;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&si, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    if (CreateProcessW(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(wr); wr = NULL;
        while (ReadFile(rd, raw + total, (DWORD)(sizeof raw - 1 - total), &got, NULL) && got) { total += got; if (total >= sizeof raw - 1) break; }
        WaitForSingleObject(pi.hProcess, 10000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        MultiByteToWideChar(CP_OEMCP, 0, raw, (int)total, out, cap - 1); out[total < (DWORD)cap - 1 ? total : (DWORD)cap - 1] = 0;
        ok = TRUE;
    }
    if (wr) CloseHandle(wr);
    CloseHandle(rd);
    return ok;
}

static BOOL AutostartTarget(wchar_t *path, int cap)
{
    wchar_t *xml = (wchar_t *)malloc(4096 * sizeof(wchar_t)); wchar_t *a, *b; BOOL ok = FALSE;
    path[0] = 0;
    if (!xml) return FALSE;
    if (RunCapture(L"schtasks.exe /query /tn " TASK_NAME L" /xml", xml, 4096) && (a = wcsstr(xml, L"<Command>")) != NULL) {
        a += 9; b = wcsstr(a, L"</Command>");
        if (b && b - a < cap) { wcsncpy(path, a, (size_t)(b - a)); path[b - a] = 0; ok = TRUE; }
    }
    free(xml);
    return ok;
}

static void XmlEscape(const wchar_t *in, wchar_t *out, size_t cap)
{
    size_t n = 0;
    for (; *in && n + 7 < cap; in++) {
        const wchar_t *r = *in == L'&' ? L"&amp;" : *in == L'<' ? L"&lt;" : *in == L'>' ? L"&gt;" : NULL;
        if (r) { wcscpy(out + n, r); n += wcslen(r); } else out[n++] = *in;
    }
    out[n] = 0;
}

static BOOL SetAutostart(BOOL on)
{
    if (!on) { DWORD d = RunHidden(L"schtasks.exe /delete /tn " TASK_NAME L" /f"); Log(L"Start with Windows: removed task -> exit %lu", (unsigned long)d); return d == 0; }
    wchar_t exe[MAX_PATH], exeX[MAX_PATH * 2], dirX[MAX_PATH * 2], user[256] = L"", userX[512], tmpDir[MAX_PATH], xmlPath[MAX_PATH], cmd[MAX_PATH + 128];
    wchar_t *xml = (wchar_t *)malloc(8192 * sizeof(wchar_t));
    BOOL ok = FALSE; DWORD un = 256;
    if (!xml) return FALSE;
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    XmlEscape(exe, exeX, MAX_PATH * 2);
    XmlEscape(g_dataDir, dirX, MAX_PATH * 2);
    if (!GetUserNameExW(NameSamCompatible, user, &un)) user[0] = 0;
    XmlEscape(user, userX, 512);
    swprintf(xml, 8192,
        L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        L"<RegistrationInfo><Description>Starts SailHighSea WinProcessKiller at logon</Description></RegistrationInfo>"
        L"<Triggers><LogonTrigger><Enabled>true</Enabled>%ls%ls%ls<Delay>PT10S</Delay></LogonTrigger></Triggers>"
        L"<Principals><Principal id=\"A\">%ls%ls%ls<LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        L"<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled></Settings>"
        L"<Actions Context=\"A\"><Exec><Command>%ls</Command><Arguments>--minimized</Arguments><WorkingDirectory>%ls</WorkingDirectory></Exec></Actions></Task>",
        user[0] ? L"<UserId>" : L"", user[0] ? userX : L"", user[0] ? L"</UserId>" : L"",
        user[0] ? L"<UserId>" : L"", user[0] ? userX : L"", user[0] ? L"</UserId>" : L"", exeX, dirX);
    GetTempPathW(MAX_PATH, tmpDir);
    swprintf(xmlPath, MAX_PATH, L"%lsshswpk-task.xml", tmpDir);
    HANDLE f = CreateFileW(xmlPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w; WORD bom = 0xFEFF;
        WriteFile(f, &bom, 2, &w, NULL);
        WriteFile(f, xml, (DWORD)(wcslen(xml) * sizeof(wchar_t)), &w, NULL);
        CloseHandle(f);
        swprintf(cmd, MAX_PATH + 128, L"schtasks.exe /create /tn " TASK_NAME L" /xml \"%ls\" /f", xmlPath);
        { DWORD c = RunHidden(cmd); ok = c == 0; Log(L"Start with Windows: created task for %ls -> exit %lu", BaseName(exe), (unsigned long)c); }
        DeleteFileW(xmlPath);
    }
    free(xml);
    return ok;
}

static void ApplyOnTop(void)
{
    SetWindowPos(g_hwnd, g_onTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

static HMENU BuildOptionsMenu(void)
{
    HMENU m = CreatePopupMenu(), th = CreatePopupMenu(), hl = CreatePopupMenu();
    AppendMenuW(m, MF_STRING | (g_autoCache > 0 ? MF_CHECKED : 0), IDM_AUTOSTART, L"Start with Windows");
    AppendMenuW(m, MF_STRING | (g_startMin ? MF_CHECKED : 0), IDM_STARTMIN, L"Start minimized to notification area");
    AppendMenuW(m, MF_STRING | (g_autoMon ? MF_CHECKED : 0), IDM_AUTOMON, L"Start monitoring when the app opens");
    AppendMenuW(m, MF_STRING | (g_closeTray ? MF_CHECKED : 0), IDM_CLOSETRAY, L"Close button hides to notification area");
    AppendMenuW(m, MF_STRING | (g_minTray ? MF_CHECKED : 0), IDM_MINTRAY, L"Minimize to notification area");
    AppendMenuW(m, MF_STRING | (g_onTop ? MF_CHECKED : 0), IDM_ONTOP, L"Always on top");
    { wchar_t hk[120], key[80]; if (g_hkVk) { HotkeyText(g_hkMods, g_hkVk, key, 80); swprintf(hk, 120, L"Shortcut to show the window: %ls...", key); } else wcscpy(hk, L"Shortcut to show the window: none...");
      AppendMenuW(m, MF_STRING, IDM_HOTKEY, hk); }
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(th, MF_STRING | (g_theme == 0 ? MF_CHECKED : 0), IDM_THEME_DARK, L"Dark");
    AppendMenuW(th, MF_STRING | (g_theme == 1 ? MF_CHECKED : 0), IDM_THEME_LIGHT, L"Light");
    AppendMenuW(th, MF_STRING | (g_theme == 2 ? MF_CHECKED : 0), IDM_THEME_SYSTEM, L"Follow Windows");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)th, L"Theme");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_WATCHED) ? MF_CHECKED : 0), IDM_HL_WATCHED, L"Watched items (red)");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_SYSTEM) ? MF_CHECKED : 0), IDM_HL_SYSTEM, L"Windows system processes (blue)");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)hl, L"Highlighting");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (g_showProc ? MF_CHECKED : 0), IDM_SHOWPROC, L"Show processes");
    AppendMenuW(m, MF_STRING | (g_showSvc ? MF_CHECKED : 0), IDM_SHOWSVC, L"Show services");
    AppendMenuW(m, MF_STRING | (g_onlyRun ? MF_CHECKED : 0), IDM_ONLYRUN, L"Show only running items");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_REFRESH, L"Refresh list\tF5");
    AppendMenuW(m, MF_STRING, IDM_KILLLOG, L"Kill log...");
    AppendMenuW(m, MF_STRING, IDM_HISTORY, L"Process history...");
    AppendMenuW(m, MF_STRING | (g_etwRunning ? MF_CHECKED : 0), IDM_HISTREC, L"Record process history");
    AppendMenuW(m, MF_STRING, IDM_FOLDER, L"Open data folder");
    AppendMenuW(m, MF_STRING, IDM_OPENLOG, L"Open debug log");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_ABOUT, L"About SailHighSea WinProcessKiller...");
    return m;
}

static void ShowAbout(void)
{
    wchar_t t[900]; int a;
    swprintf(t, 900,
        L"%ls  v%ls\n\n"
        L"A tiny, portable, open-source Windows tool that keeps the processes and services you choose from running. Pick an item, click Kill & Watch, and it is ended again every time it starts.\n\n"
        L"MIT License. Copyright (c) 2026 SailHighSea WinProcessKiller contributors.\n"
        L"github.com/SailHighSea/sailhighsea-wpk\n\n"
        L"Settings, the watch list and the debug log are kept next to the program:\n%ls",
        APP_NAME, APP_VERSION, g_dataDir);
    a = ShowDialog(g_hwnd, L"About " APP_NAME, t, L"Close", L"GitHub page", L"Data folder");
    if (a == 2) ShellExecuteW(g_hwnd, L"open", L"https://github.com/SailHighSea/sailhighsea-wpk", NULL, NULL, SW_SHOWNORMAL);
    else if (a == 3) ShellExecuteW(g_hwnd, L"open", g_dataDir, NULL, NULL, SW_SHOWNORMAL);
}

static void ShowOptionsMenu(void)
{
    RECT r; GetWindowRect(g_bOptions, &r);
    HMENU m = BuildOptionsMenu();
    g_menuOpen = TRUE;
    TrackPopupMenu(m, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, r.left, r.bottom, 0, g_hwnd, NULL);
    g_menuOpen = FALSE;
    DestroyMenu(m);
}

static void DrawStatusBar(const DRAWITEMSTRUCT *di)
{
    RECT r = di->rcItem; HGDIOBJ of = SelectObject(di->hDC, g_font);
    FillRect(di->hDC, &r, g_editBrush);
    SetBkMode(di->hDC, TRANSPARENT);
    SetTextColor(di->hDC, MonitorOn() ? COL_GREEN : COL_RED);
    r.left += 12;
    DrawTextW(di->hDC, L"\u25CF", -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT);
    SetTextColor(di->hDC, COL_DIM);
    r.left += 20;
    DrawTextW(di->hDC, g_statusText, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS);
    SelectObject(di->hDC, of);
}

/* ---------- kill log window ---------- */
static KillEntry *g_lsnap; static int g_nlsnap;
static HWND g_lbUnwatch, g_lbCopy, g_lbClear;

static void LogRowText(const KillEntry *e, int c, wchar_t *o, int cap)
{
    switch (c) {
    case 0: swprintf(o, (size_t)cap, L"%02d:%02d:%02d", e->t.wHour, e->t.wMinute, e->t.wSecond); break;
    case 1: wcsncpy(o, e->label, (size_t)cap - 1); o[cap - 1] = 0; break;
    case 2: wcscpy(o, e->kind == K_SVC ? L"Service" : L"Process"); break;
    case 3: wcsncpy(o, e->result, (size_t)cap - 1); o[cap - 1] = 0; break;
    case 4: swprintf(o, (size_t)cap, L"%u", e->count); break;
    default: wcsncpy(o, e->path, (size_t)cap - 1); o[cap - 1] = 0; break;
    }
}

static void LogWndRefresh(void)
{
    int skind = -1, sel; wchar_t sid[MAX_PATH] = L"", sres[48] = L"";
    if (!g_logWnd) return;
    sel = ListView_GetNextItem(g_logList, -1, LVNI_SELECTED);
    if (sel >= 0 && sel < g_nlsnap) { skind = g_lsnap[sel].kind; wcscpy(sid, g_lsnap[sel].id); wcscpy(sres, g_lsnap[sel].result); }
    EnterCriticalSection(&g_cs);
    free(g_lsnap);
    g_lsnap = (KillEntry *)malloc((size_t)(g_nklog > 0 ? g_nklog : 1) * sizeof(KillEntry));
    g_nlsnap = g_lsnap ? g_nklog : 0;
    if (g_lsnap && g_nlsnap) memcpy(g_lsnap, g_klog, (size_t)g_nlsnap * sizeof(KillEntry));
    LeaveCriticalSection(&g_cs);
    ListView_SetItemCountEx(g_logList, g_nlsnap, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    ListView_SetItemState(g_logList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (skind >= 0)
        for (int i = 0; i < g_nlsnap; i++)
            if (g_lsnap[i].kind == skind && _wcsicmp(g_lsnap[i].id, sid) == 0 && wcscmp(g_lsnap[i].result, sres) == 0) {
                ListView_SetItemState(g_logList, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                break;
            }
    InvalidateRect(g_logList, NULL, TRUE);
}

static void LogLayout(HWND h)
{
    RECT rc; UINT dpi = GetDpiForWindow(h);
    #define S(v) MulDiv((v), (int)dpi, 96)
    int mg = S(12), bw = S(130), bh = S(34), gap = S(8), by, x, used;
    GetClientRect(h, &rc);
    by = rc.bottom - mg - bh; x = rc.right - mg - 3 * bw - 2 * gap;
    MoveWindow(g_logList, 0, 0, rc.right, by - mg, TRUE);
    MoveWindow(g_lbUnwatch, x, by, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_lbCopy, x, by, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_lbClear, x, by, bw, bh, TRUE);
    used = S(90) + S(240) + S(80) + S(200) + S(70);
    ListView_SetColumnWidth(g_logList, 0, S(90)); ListView_SetColumnWidth(g_logList, 1, S(240)); ListView_SetColumnWidth(g_logList, 2, S(80));
    ListView_SetColumnWidth(g_logList, 3, S(200)); ListView_SetColumnWidth(g_logList, 4, S(70));
    ListView_SetColumnWidth(g_logList, 5, max(S(120), rc.right - used - GetSystemMetrics(SM_CXVSCROLL) - 4));
    #undef S
}

static void LogCopy(void)
{
    int sel = ListView_GetNextItem(g_logList, -1, LVNI_SELECTED);
    size_t cap = (size_t)(g_nlsnap + 1) * 1200; wchar_t *buf = (wchar_t *)malloc(cap * sizeof(wchar_t)), cell[MAX_PATH]; size_t n = 0;
    if (!buf) return;
    buf[0] = 0;
    for (int i = (sel >= 0 ? sel : 0); i < g_nlsnap && (sel < 0 || i == sel); i++) {          /* the selected row, or everything */
        for (int c = 0; c < 6; c++) { LogRowText(&g_lsnap[i], c, cell, MAX_PATH); n += (size_t)swprintf(buf + n, cap - n, L"%ls%ls", cell, c < 5 ? L"\t" : L"\r\n"); }
    }
    CopyToClipboard(g_logWnd, buf);
    free(buf);
}

static LRESULT CALLBACK LogProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE: {
        LVCOLUMNW col; HWND hdr;
        g_logWnd = h;
        g_logList = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
                                    0, 0, 10, 10, h, (HMENU)IDC_LOG_LIST, g_inst, NULL);
        SendMessageW(g_logList, WM_SETFONT, (WPARAM)g_font, TRUE);
        ListView_SetExtendedListViewStyle(g_logList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        ListView_SetBkColor(g_logList, cBg); ListView_SetTextBkColor(g_logList, cBg); ListView_SetTextColor(g_logList, cText);
        ThemeCtl(g_logList);
        hdr = ListView_GetHeader(g_logList);
        SetWindowSubclass(hdr, HeaderProc, 1, 0);
        SetPropW(hdr, L"nosort", (HANDLE)1); SetPropW(hdr, L"ralign", (HANDLE)(UINT_PTR)0x10);
        ZeroMemory(&col, sizeof col); col.mask = LVCF_TEXT | LVCF_WIDTH; col.cx = 100;
        col.pszText = L"Last seen"; ListView_InsertColumn(g_logList, 0, &col);
        col.pszText = L"Name"; ListView_InsertColumn(g_logList, 1, &col);
        col.pszText = L"Type"; ListView_InsertColumn(g_logList, 2, &col);
        col.pszText = L"Result"; ListView_InsertColumn(g_logList, 3, &col);
        col.pszText = L"Count"; ListView_InsertColumn(g_logList, 4, &col);
        col.pszText = L"Path / Service name"; ListView_InsertColumn(g_logList, 5, &col);
        g_lbUnwatch = MakeChild(h, L"BUTTON", L"Stop Watching", BS_OWNERDRAW, 0, 0, 10, 10, IDC_LOG_UNWATCH);
        g_lbCopy = MakeChild(h, L"BUTTON", L"Copy", BS_OWNERDRAW, 0, 0, 10, 10, IDC_LOG_COPY);
        g_lbClear = MakeChild(h, L"BUTTON", L"Clear", BS_OWNERDRAW, 0, 0, 10, 10, IDC_LOG_CLEAR);
        FlatButton(g_lbUnwatch); FlatButton(g_lbCopy); FlatButton(g_lbClear);
        return 0;
    }
    case WM_SIZE:
        LogLayout(h);
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)l)->ptMinTrackSize.x = MulDiv(760, (int)GetDpiForWindow(h), 96);
        ((MINMAXINFO *)l)->ptMinTrackSize.y = MulDiv(300, (int)GetDpiForWindow(h), 96);
        return 0;
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(h, &rc); FillRect((HDC)w, &rc, g_bgBrush);
        return 1;
    }
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_NOTIFY: {
        NMHDR *nh = (NMHDR *)l;
        if (nh->hwndFrom != g_logList) break;
        if (nh->code == LVN_GETDISPINFOW) {
            NMLVDISPINFOW *d = (NMLVDISPINFOW *)nh;
            if ((d->item.mask & LVIF_TEXT) && d->item.iItem >= 0 && d->item.iItem < g_nlsnap) LogRowText(&g_lsnap[d->item.iItem], d->item.iSubItem, d->item.pszText, d->item.cchTextMax);
            return 0;
        }
        if (nh->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)nh;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int i = (int)cd->nmcd.dwItemSpec;
                cd->clrText = (i >= 0 && i < g_nlsnap && g_lsnap[i].fail) ? cRed : cText;   /* failed kills in red */
                return CDRF_NEWFONT;
            }
        }
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_LOG_UNWATCH: {
            int sel = ListView_GetNextItem(g_logList, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < g_nlsnap) {
                wchar_t id[MAX_PATH]; int kind = g_lsnap[sel].kind; BOOL had;
                wcscpy(id, g_lsnap[sel].id);
                EnterCriticalSection(&g_cs); had = FindRuleIdx(kind, id) >= 0; LeaveCriticalSection(&g_cs);
                if (had) { RemoveRule(kind, id); RefreshApps(); }
                else ShowDialog(h, APP_NAME, L"This item is not on the watch list (anymore).", L"OK", NULL, NULL);
            }
            break;
        }
        case IDC_LOG_COPY: LogCopy(); break;
        case IDC_LOG_CLEAR:
            EnterCriticalSection(&g_cs); g_nklog = 0; LeaveCriticalSection(&g_cs);
            LogWndRefresh();
            break;
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        g_logWnd = NULL; g_logList = NULL;
        free(g_lsnap); g_lsnap = NULL; g_nlsnap = 0;
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static void ShowKillLog(void)
{
    static BOOL registered; BOOL dark = g_dark; UINT dpi; RECT wa; int pref = 2;
    if (g_logWnd) { if (IsIconic(g_logWnd)) ShowWindow(g_logWnd, SW_RESTORE); SetForegroundWindow(g_logWnd); LogWndRefresh(); return; }
    if (!registered) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = LogProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSWPKLog"; wc.hIcon = g_iconBig;
        RegisterClassW(&wc); registered = TRUE;
    }
    dpi = GetDpiForWindow(g_hwnd); GetWindowRect(g_hwnd, &wa);
    g_logWnd = CreateWindowExW(0, L"SHSWPKLog", L"Kill log - processes and services killed this session", WS_OVERLAPPEDWINDOW,
                               wa.left + MulDiv(40, (int)dpi, 96), wa.top + MulDiv(40, (int)dpi, 96), MulDiv(1000, (int)dpi, 96), MulDiv(540, (int)dpi, 96), NULL, NULL, g_inst, NULL);
    if (!g_logWnd) return;
    if (g_iconSmall) SendMessageW(g_logWnd, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    if (g_iconBig) SendMessageW(g_logWnd, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    DwmSetWindowAttribute(g_logWnd, 20, &dark, sizeof dark);
    DwmSetWindowAttribute(g_logWnd, 33, &pref, sizeof pref);
    LogLayout(g_logWnd);
    LogWndRefresh();
    ShowWindow(g_logWnd, SW_SHOW);
}

/* ------------------------------------------------------------------ */
/* Process history: every process start / exit, caught by Windows' own  */
/* event tracing (ETW, "NT Kernel Logger") - so even programs that live */
/* for a few milliseconds are seen. Needs administrator (we have it).   */
/* ------------------------------------------------------------------ */
typedef struct {
    FILETIME start, end; BOOL ended; DWORD pid, ppid; LONG exitCode;
    wchar_t name[64], parent[64], path[MAX_PATH], cmd[400];
} HistEntry;
#define HIST_MAX 4000

static const GUID k_sysTraceGuid = { 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };
static const GUID k_procGuid = { 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };

static CRITICAL_SECTION g_hcs; static BOOL g_hcsReady;
static HistEntry *g_hist; static int g_nhist;
static volatile LONG g_histSeq;
static HANDLE g_etwThread, g_histFile = INVALID_HANDLE_VALUE;
typedef struct { DWORD pid; wchar_t name[64]; } PidName;
static PidName *g_pidName;                    /* 4096 slots, allocated when recording starts */

static void HistInitOnce(void)
{
    if (g_hcsReady) return;
    InitializeCriticalSection(&g_hcs);
    g_hist = (HistEntry *)calloc(HIST_MAX, sizeof(HistEntry));
    g_pidName = (PidName *)calloc(4096, sizeof(PidName));
    g_hcsReady = TRUE;
}

static void FileTimeText(const FILETIME *ft, BOOL withDate, wchar_t *o, size_t cap)
{
    FILETIME lf; SYSTEMTIME st;
    FileTimeToLocalFileTime(ft, &lf); FileTimeToSystemTime(&lf, &st);
    if (withDate) swprintf(o, cap, L"%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    else swprintf(o, cap, L"%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static unsigned long long FtU64(const FILETIME *f) { return ((unsigned long long)f->dwHighDateTime << 32) | f->dwLowDateTime; }

static void HistFileOpen(void)
{
    wchar_t f[MAX_PATH], old[MAX_PATH]; WIN32_FILE_ATTRIBUTE_DATA fa;
    swprintf(f, MAX_PATH, L"%ls\\process-history.txt", g_dataDir);
    if (GetFileAttributesExW(f, GetFileExInfoStandard, &fa) && fa.nFileSizeLow > 8u * 1024 * 1024) {
        swprintf(old, MAX_PATH, L"%ls\\process-history.old.txt", g_dataDir);
        MoveFileExW(f, old, MOVEFILE_REPLACE_EXISTING);
    }
    g_histFile = CreateFileW(f, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

/* One tab-separated line per event: time, START/EXIT, pid, parent pid, name, parent, lifetime-ms/exit code, path, command line. */
static void HistFileWrite(const wchar_t *what, const HistEntry *e, const FILETIME *when)
{
    wchar_t line[1400], ts[40], extra[48] = L""; char u8[4200]; int n; DWORD wr;
    if (g_histFile == INVALID_HANDLE_VALUE) return;
    FileTimeText(when, TRUE, ts, 40);
    if (e->ended && wcscmp(what, L"EXIT") == 0) swprintf(extra, 48, L"%llu ms / code %ld", (FtU64(&e->end) - FtU64(&e->start)) / 10000ull, (long)e->exitCode);
    swprintf(line, 1400, L"%ls\t%ls\t%lu\t%lu\t%ls\t%ls\t%ls\t%ls\t%ls\r\n", ts, what, (unsigned long)e->pid, (unsigned long)e->ppid,
             e->name, e->parent, extra, e->path, e->cmd);
    n = WideCharToMultiByte(CP_UTF8, 0, line, -1, u8, sizeof u8, NULL, NULL);
    if (n > 1) WriteFile(g_histFile, u8, (DWORD)(n - 1), &wr, NULL);
}

static BOOL QueryPidPath(DWORD pid, wchar_t *path, DWORD cap)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); DWORD n = cap; BOOL ok = FALSE;
    if (!h) return FALSE;
    if (QueryFullProcessImageNameW(h, 0, path, &n) && n > 0) ok = TRUE;
    CloseHandle(h);
    return ok;
}

/* First program path / name in a command line ("C:\x y\z.exe" args, or C:\x\z.exe args, or z.exe args). */
static void CmdFirstToken(const wchar_t *cmd, wchar_t *out, size_t cap)
{
    const wchar_t *s = cmd, *e; size_t n;
    out[0] = 0;
    while (*s == L' ') s++;
    if (wcsncmp(s, L"\\??\\", 4) == 0) s += 4;
    if (*s == L'"') {
        s++; e = wcschr(s, L'"'); n = e ? (size_t)(e - s) : wcslen(s);
    } else {
        const wchar_t *p = s; e = NULL;
        for (; *p; p++) if (p[0] == L'.' && (p[1] | 0x20) == L'e' && (p[2] | 0x20) == L'x' && (p[3] | 0x20) == L'e' && (p[4] == 0 || p[4] == L' ' || p[4] == L'"')) { e = p + 4; break; }
        if (!e) { e = wcschr(s, L' '); }
        n = e ? (size_t)(e - s) : wcslen(s);
    }
    if (n >= cap) n = cap - 1;
    wcsncpy(out, s, n); out[n] = 0;
}

/* Parse a kernel-logger process start/end record. Layout (x64): key(8) pid(4) ppid(4) session(4) exitStatus(4)
 * pageDirBase(8) [flags(4) on version 4+] userSid(variable) imageFileName(ansi) commandLine(utf-16) ...        */
static BOOL ParseProcRecord(const EVENT_RECORD *er, DWORD *pid, DWORD *ppid, LONG *exitSt, wchar_t *img, size_t imgCap, wchar_t *cmd, size_t cmdCap)
{
    const BYTE *d = (const BYTE *)er->UserData; ULONG n = er->UserDataLength; int ver = er->EventHeader.EventDescriptor.Version;
    if (!d || n < 44) return FALSE;
    *pid = *(const DWORD *)(d + 8); *ppid = *(const DWORD *)(d + 12); *exitSt = *(const LONG *)(d + 20);
    for (int variant = 0; variant < 2; variant++) {
        ULONG off = 32 + ((variant == 0) == (ver >= 4) ? 4 : 0), s, len; BOOL okName = TRUE;
        if (off + 4 > n) continue;
        if (*(const DWORD *)(d + off) != 0) {
            off += 16;                                           /* TOKEN_USER: SID pointer + attributes */
            if (off + 8 > n) continue;
            if (d[off + 1] > 15) continue;
            off += 8 + 4u * d[off + 1];
        } else off += 4;
        if (off >= n) continue;
        for (s = off; s < n && d[s]; s++) if (d[s] < 0x20 || d[s] == 0xFF) okName = FALSE;
        if (s >= n || !okName || s == off) continue;             /* image name must be printable text */
        len = s - off;
        if (len >= imgCap) len = (ULONG)imgCap - 1;
        MultiByteToWideChar(CP_ACP, 0, (const char *)d + off, (int)len, img, (int)imgCap); img[len] = 0;
        off = s + 1; cmd[0] = 0;
        if (off + 2 <= n) {
            size_t k = 0; const wchar_t *w = (const wchar_t *)(d + off), *wend = (const wchar_t *)(d + n);
            while (w + k < wend && w[k] && k + 1 < cmdCap) { cmd[k] = w[k]; k++; }
            cmd[k] = 0;
        }
        return TRUE;
    }
    return FALSE;
}

static void PidNameSet(DWORD pid, const wchar_t *name)
{
    int i = (int)(pid & 4095);
    g_pidName[i].pid = pid; wcsncpy(g_pidName[i].name, name, 63); g_pidName[i].name[63] = 0;
}

static void HistOnStart(const FILETIME *ts, DWORD pid, DWORD ppid, const wchar_t *img, const wchar_t *cmd)
{
    HistEntry *e; wchar_t path[MAX_PATH] = L"", tok[MAX_PATH], parent[64] = L"";
    EnterCriticalSection(&g_hcs);
    if (g_nhist >= HIST_MAX) { memmove(g_hist, g_hist + 500, (size_t)(HIST_MAX - 500) * sizeof(HistEntry)); g_nhist = HIST_MAX - 500; }
    e = &g_hist[g_nhist++];
    ZeroMemory(e, sizeof *e);
    e->start = *ts; e->pid = pid; e->ppid = ppid;
    if (!QueryPidPath(pid, path, MAX_PATH)) path[0] = 0;
    CmdFirstToken(cmd, tok, MAX_PATH);
    if (path[0]) wcsncpy(e->name, BaseName(path), 63);
    else if (tok[0] && wcschr(tok, L'\\') && _wcsnicmp(BaseName(tok), img, wcslen(img) < 12 ? wcslen(img) : 12) == 0) { wcsncpy(e->name, BaseName(tok), 63); wcsncpy(path, tok, MAX_PATH - 1); path[MAX_PATH - 1] = 0; }
    else if (tok[0] && _wcsnicmp(tok, img, wcslen(img) < 12 ? wcslen(img) : 12) == 0 && wcslen(tok) >= wcslen(img)) wcsncpy(e->name, BaseName(tok), 63);
    else wcsncpy(e->name, img, 63);
    wcsncpy(e->path, path, MAX_PATH - 1);
    wcsncpy(e->cmd, cmd, 399);
    if (g_pidName[ppid & 4095].pid == ppid) wcscpy(parent, g_pidName[ppid & 4095].name);
    else { wchar_t pp[MAX_PATH]; if (QueryPidPath(ppid, pp, MAX_PATH)) wcsncpy(parent, BaseName(pp), 63); }
    wcsncpy(e->parent, parent, 63);
    PidNameSet(pid, e->name);
    HistFileWrite(L"START", e, ts);
    InterlockedIncrement(&g_histSeq);
    LeaveCriticalSection(&g_hcs);
}

static void HistOnExit(const FILETIME *ts, DWORD pid, LONG code)
{
    EnterCriticalSection(&g_hcs);
    for (int i = g_nhist - 1, seen = 0; i >= 0 && seen < 3000; i--, seen++)
        if (g_hist[i].pid == pid && !g_hist[i].ended) {
            g_hist[i].ended = TRUE; g_hist[i].end = *ts; g_hist[i].exitCode = code;
            HistFileWrite(L"EXIT", &g_hist[i], ts);
            InterlockedIncrement(&g_histSeq);
            break;
        }
    LeaveCriticalSection(&g_hcs);
}

static VOID WINAPI EtwEvent(PEVENT_RECORD er)
{
    DWORD pid, ppid; LONG st; wchar_t img[64], cmd[400]; FILETIME ts; ULONGLONG t;
    UCHAR op;
    if (!IsEqualGUID(&er->EventHeader.ProviderId, &k_procGuid)) return;
    op = er->EventHeader.EventDescriptor.Opcode;
    if (op != 1 && op != 2) return;                              /* 1 = process start, 2 = process end */
    if (!ParseProcRecord(er, &pid, &ppid, &st, img, 64, cmd, 400)) return;
    t = (ULONGLONG)er->EventHeader.TimeStamp.QuadPart; ts.dwLowDateTime = (DWORD)t; ts.dwHighDateTime = (DWORD)(t >> 32);
    if (op == 1) HistOnStart(&ts, pid, ppid, img, cmd); else HistOnExit(&ts, pid, st);
}

static DWORD WINAPI EtwThread(LPVOID p)
{
    EVENT_TRACE_LOGFILEW lf; TRACEHANDLE h;
    ZeroMemory(&lf, sizeof lf);
    lf.LoggerName = (LPWSTR)KERNEL_LOGGER_NAMEW;
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = EtwEvent;
    h = OpenTraceW(&lf);
    if (h == (TRACEHANDLE)INVALID_HANDLE_VALUE) { Log(L"Process history: OpenTrace failed, error %lu", GetLastError()); return 1; }
    ProcessTrace(&h, 1, NULL, NULL);                             /* blocks until the session is stopped */
    CloseTrace(h);
    return 0;
}

static EVENT_TRACE_PROPERTIES *NewTraceProps(void)
{
    size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES *pr = (EVENT_TRACE_PROPERTIES *)calloc(1, sz);
    if (!pr) return NULL;
    pr->Wnode.BufferSize = (ULONG)sz;
    pr->Wnode.Guid = k_sysTraceGuid;
    pr->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pr->Wnode.ClientContext = 2;                                 /* time stamps as FILETIME */
    pr->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pr->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    pr->FlushTimer = 1;
    pr->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return pr;
}

static void StopHistory(void)
{
    EVENT_TRACE_PROPERTIES *pr;
    if (!g_etwRunning) return;
    pr = NewTraceProps();
    if (pr) { ControlTraceW(0, KERNEL_LOGGER_NAMEW, pr, EVENT_TRACE_CONTROL_STOP); free(pr); }
    if (g_etwThread) { WaitForSingleObject(g_etwThread, 4000); CloseHandle(g_etwThread); g_etwThread = NULL; }
    if (g_histFile != INVALID_HANDLE_VALUE) { CloseHandle(g_histFile); g_histFile = INVALID_HANDLE_VALUE; }
    g_etwRunning = FALSE;
    Log(L"Process history: recording stopped");
}

/* Returns 0 on success, otherwise the Windows error code. */
static ULONG StartHistory(void)
{
    EVENT_TRACE_PROPERTIES *pr; TRACEHANDLE session = 0; ULONG r; HANDLE snap;
    HistInitOnce();
    if (!g_hist || !g_pidName) return ERROR_OUTOFMEMORY;
    if (g_etwRunning) return 0;
    pr = NewTraceProps();
    if (!pr) return ERROR_OUTOFMEMORY;
    r = StartTraceW(&session, KERNEL_LOGGER_NAMEW, pr);
    if (r == ERROR_ALREADY_EXISTS || r == ERROR_ACCESS_DENIED) {
        /* A leftover session (for example from a crashed earlier run) - stop it and try once more. */
        EVENT_TRACE_PROPERTIES *st = NewTraceProps();
        if (st) { ControlTraceW(0, KERNEL_LOGGER_NAMEW, st, EVENT_TRACE_CONTROL_STOP); free(st); }
        free(pr); pr = NewTraceProps();
        if (!pr) return ERROR_OUTOFMEMORY;
        session = 0;
        r = StartTraceW(&session, KERNEL_LOGGER_NAMEW, pr);
    }
    free(pr);
    if (r != ERROR_SUCCESS) { Log(L"Process history: StartTrace failed, error %lu", r); return r; }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);          /* so parents that started earlier have a name */
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof pe;
        EnterCriticalSection(&g_hcs);
        if (Process32FirstW(snap, &pe)) do PidNameSet(pe.th32ProcessID, pe.szExeFile); while (Process32NextW(snap, &pe));
        LeaveCriticalSection(&g_hcs);
        CloseHandle(snap);
    }
    HistFileOpen();
    g_etwThread = CreateThread(NULL, 0, EtwThread, NULL, 0, NULL);
    if (!g_etwThread) {
        EVENT_TRACE_PROPERTIES *st = NewTraceProps();
        if (st) { ControlTraceW(0, KERNEL_LOGGER_NAMEW, st, EVENT_TRACE_CONTROL_STOP); free(st); }
        return GetLastError();
    }
    g_etwRunning = TRUE;
    Log(L"Process history: recording started");
    return 0;
}

/* ---------- process history window ---------- */
enum { IDC_H_LIST = 711, IDC_H_REC, IDC_H_SHORT, IDC_H_WATCH, IDC_H_COPY, IDC_H_CLEAR, IDC_H_EDIT };
#define HCOLS 8
static HistEntry *g_hsnap; static int g_nhsnap; static LONG g_hsnapSeq = -1;
static HWND g_hbRec, g_hbShort, g_hbWatch, g_hbCopy, g_hbClear;
static int g_hSortCol = -1; static BOOL g_hSortAsc;              /* -1 = no column chosen: newest first, no arrow */
static BOOL g_hShort;                                            /* show only programs that lived less than 5 seconds */

static BOOL ContainsCI(const wchar_t *hay, const wchar_t *needle)
{
    size_t n = wcslen(needle);
    if (!n) return TRUE;
    for (; *hay; hay++) if (_wcsnicmp(hay, needle, n) == 0) return TRUE;
    return FALSE;
}

static void FormatLasted(const HistEntry *e, wchar_t *o, size_t cap)
{
    unsigned long long ms;
    if (!e->ended) { o[0] = 0; return; }
    ms = (FtU64(&e->end) - FtU64(&e->start)) / 10000ull;
    if (FtU64(&e->end) < FtU64(&e->start)) ms = 0;
    if (ms < 1000) swprintf(o, cap, L"%llu ms", ms);
    else if (ms < 60000) swprintf(o, cap, L"%.1f s", (double)ms / 1000.0);
    else if (ms < 3600000) swprintf(o, cap, L"%llu m %llu s", ms / 60000, (ms / 1000) % 60);
    else swprintf(o, cap, L"%llu h %llu m", ms / 3600000, (ms / 60000) % 60);
}

static int HistCmp(const void *a, const void *b)
{
    const HistEntry *x = (const HistEntry *)a, *y = (const HistEntry *)b; unsigned long long kx = 0, ky = 0; int r = 0;
    int col = g_hSortCol < 0 ? 0 : g_hSortCol; BOOL asc = g_hSortCol < 0 ? FALSE : g_hSortAsc;
    switch (col) {
    case 0: kx = FtU64(&x->start); ky = FtU64(&y->start); break;
    case 1: kx = x->ended ? FtU64(&x->end) : ~0ull; ky = y->ended ? FtU64(&y->end) : ~0ull; break;      /* still running = newest */
    case 2: kx = x->ended ? FtU64(&x->end) - FtU64(&x->start) : ~0ull; ky = y->ended ? FtU64(&y->end) - FtU64(&y->start) : ~0ull; break;
    case 4: kx = x->pid; ky = y->pid; break;
    case 3: r = _wcsicmp(x->name, y->name); break;
    case 5: r = _wcsicmp(x->parent, y->parent); break;
    case 6: r = _wcsicmp(x->cmd, y->cmd); break;
    default: r = _wcsicmp(x->path, y->path); break;
    }
    if (col <= 2 || col == 4) r = kx < ky ? -1 : kx > ky ? 1 : 0;
    if (!asc) r = -r;
    if (r == 0) { kx = FtU64(&x->start); ky = FtU64(&y->start); r = kx < ky ? 1 : kx > ky ? -1 : 0; }   /* ties: newest first */
    return r;
}

static void HistRowText(const HistEntry *e, int c, wchar_t *o, int cap)
{
    wchar_t t[80];
    o[0] = 0;
    switch (c) {
    case 0: FileTimeText(&e->start, TRUE, t, 80); wcsncpy(o, t, (size_t)cap - 1); break;
    case 1: if (e->ended) { FileTimeText(&e->end, FALSE, t, 80); wcsncpy(o, t, (size_t)cap - 1); } else wcsncpy(o, L"running", (size_t)cap - 1); break;
    case 2: FormatLasted(e, t, 80); wcsncpy(o, t, (size_t)cap - 1); break;
    case 3: wcsncpy(o, e->name, (size_t)cap - 1); break;
    case 4: swprintf(o, (size_t)cap, L"%lu", (unsigned long)e->pid); break;
    case 5: wcsncpy(o, e->parent, (size_t)cap - 1); break;
    case 6: wcsncpy(o, e->cmd, (size_t)cap - 1); break;
    default: wcsncpy(o, e->path, (size_t)cap - 1); break;
    }
    o[cap - 1] = 0;
}

static void HistUiState(void)
{
    if (!g_histWnd) return;
    SetWindowTextW(g_histWnd, g_etwRunning ? L"Process history - recording every program that starts and exits" : L"Process history - NOT recording (press Recording: Off to start)");
    SetWindowTextW(g_hbRec, g_etwRunning ? L"Recording: On" : L"Recording: Off");
    SetWindowTextW(g_hbShort, g_hShort ? L"Short-lived: On" : L"Short-lived: Off");
    InvalidateRect(g_hbRec, NULL, TRUE); InvalidateRect(g_hbShort, NULL, TRUE);
}

static void HistWndRefresh(BOOL force)
{
    DWORD spid = 0; FILETIME sst = {0, 0}; int sel, i, n = 0; wchar_t filt[120];
    if (!g_histWnd || !g_hcsReady) return;
    if (!force && g_histSeq == g_hsnapSeq) return;
    sel = ListView_GetNextItem(g_histList, -1, LVNI_SELECTED);
    if (sel >= 0 && sel < g_nhsnap) { spid = g_hsnap[sel].pid; sst = g_hsnap[sel].start; }
    GetWindowTextW(g_histEdit, filt, 120);
    free(g_hsnap); g_hsnap = NULL; g_nhsnap = 0;
    EnterCriticalSection(&g_hcs);
    g_hsnapSeq = g_histSeq;
    g_hsnap = (HistEntry *)malloc((size_t)(g_nhist > 0 ? g_nhist : 1) * sizeof(HistEntry));
    if (g_hsnap) {
        for (i = g_nhist - 1; i >= 0; i--) {                      /* newest first */
            const HistEntry *e = &g_hist[i];
            if (g_hShort && !(e->ended && (FtU64(&e->end) - FtU64(&e->start)) / 10000ull < 5000)) continue;
            if (filt[0] && !(ContainsCI(e->name, filt) || ContainsCI(e->path, filt) || ContainsCI(e->cmd, filt) || ContainsCI(e->parent, filt))) continue;
            g_hsnap[n++] = *e;
        }
    }
    LeaveCriticalSection(&g_hcs);
    g_nhsnap = n;
    if (n > 1) qsort(g_hsnap, (size_t)n, sizeof(HistEntry), HistCmp);
    ListView_SetItemCountEx(g_histList, g_nhsnap, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    ListView_SetItemState(g_histList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (spid)
        for (i = 0; i < g_nhsnap; i++)
            if (g_hsnap[i].pid == spid && FtU64(&g_hsnap[i].start) == FtU64(&sst)) {
                ListView_SetItemState(g_histList, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                break;
            }
    InvalidateRect(g_histList, NULL, TRUE);
}

static void HistLayout(HWND h)
{
    RECT rc; UINT dpi = GetDpiForWindow(h);
    #define S(v) MulDiv((v), (int)dpi, 96)
    int mg = S(12), bw = S(124), bh = S(34), gap = S(8), by, x, ew, used, W[HCOLS] = { 160, 90, 80, 170, 60, 150, 360, 0 };
    GetClientRect(h, &rc);
    by = rc.bottom - mg - bh; x = rc.right - mg - 5 * bw - 4 * gap;
    MoveWindow(g_histList, 0, 0, rc.right, by - mg, TRUE);
    ew = x - gap - mg;
    MoveWindow(g_histEdit, mg, by + (bh - S(26)) / 2, ew > S(80) ? ew : S(80), S(26), TRUE);
    MoveWindow(g_hbRec, x, by, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_hbShort, x, by, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_hbWatch, x, by, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_hbCopy, x, by, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_hbClear, x, by, bw, bh, TRUE);
    for (used = 0, x = 0; x < HCOLS - 1; x++) { ListView_SetColumnWidth(g_histList, x, S(W[x])); used += S(W[x]); }
    ListView_SetColumnWidth(g_histList, HCOLS - 1, max(S(200), rc.right - used - GetSystemMetrics(SM_CXVSCROLL) - 4));
    #undef S
}

static void HistCopy(void)
{
    int sel = ListView_GetNextItem(g_histList, -1, LVNI_SELECTED);
    size_t cap = (size_t)(g_nhsnap + 1) * 1400; wchar_t *buf = (wchar_t *)malloc(cap * sizeof(wchar_t)), cell[MAX_PATH]; size_t n = 0;
    if (!buf) return;
    buf[0] = 0;
    for (int i = (sel >= 0 ? sel : 0); i < g_nhsnap && (sel < 0 || i == sel); i++)
        for (int c = 0; c < HCOLS; c++) { HistRowText(&g_hsnap[i], c, cell, MAX_PATH); n += (size_t)swprintf(buf + n, cap - n, L"%ls%ls", cell, c < HCOLS - 1 ? L"\t" : L"\r\n"); }
    CopyToClipboard(g_histWnd, buf);
    free(buf);
}

static void HistWatchSelected(void)
{
    int sel = ListView_GetNextItem(g_histList, -1, LVNI_SELECTED); Item tmp; size_t len;
    if (sel < 0 || sel >= g_nhsnap) { ShowDialog(g_histWnd, APP_NAME, L"Select a program in the list first.", L"OK", NULL, NULL); return; }
    len = wcslen(g_hsnap[sel].name);
    if (len < 5 || _wcsicmp(g_hsnap[sel].name + len - 4, L".exe") != 0) {
        ShowDialog(g_histWnd, APP_NAME, L"The full program name could not be worked out for this entry (it ended too quickly to look up), so it cannot be added to the watch list.", L"OK", NULL, NULL);
        return;
    }
    ZeroMemory(&tmp, sizeof tmp);
    tmp.kind = K_PROC; wcscpy(tmp.id, g_hsnap[sel].name); wcscpy(tmp.name, tmp.id);
    if (g_hsnap[sel].path[0]) { wcscpy(tmp.detail, g_hsnap[sel].path); tmp.havePath = TRUE; }
    tmp.system = g_hsnap[sel].path[0] && g_winDir[0] && _wcsnicmp(g_hsnap[sel].path, g_winDir, wcslen(g_winDir)) == 0;
    WatchItem(&tmp);
}

static void HistToggleRecording(void)
{
    if (g_etwRunning) { StopHistory(); g_histRec = FALSE; }
    else {
        ULONG r = StartHistory();
        if (r) {
            wchar_t m[300]; swprintf(m, 300, L"Windows would not start the process event trace (error %lu). It needs administrator rights, and only one program can use the kernel trace at a time.", (unsigned long)r);
            ShowDialog(g_histWnd ? g_histWnd : g_hwnd, APP_NAME, m, L"OK", NULL, NULL);
            g_histRec = FALSE;
        } else g_histRec = TRUE;
    }
    SaveSettings();
    HistUiState();
}

static LRESULT CALLBACK HistProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE: {
        LVCOLUMNW col; HWND hdr; static const wchar_t *names[HCOLS] = { L"Started", L"Ended", L"Lasted", L"Name", L"PID", L"Parent", L"Command line", L"Path" };
        g_histWnd = h;
        g_histList = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
                                     0, 0, 10, 10, h, (HMENU)IDC_H_LIST, g_inst, NULL);
        SendMessageW(g_histList, WM_SETFONT, (WPARAM)g_font, TRUE);
        ListView_SetExtendedListViewStyle(g_histList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        ListView_SetBkColor(g_histList, cBg); ListView_SetTextBkColor(g_histList, cBg); ListView_SetTextColor(g_histList, cText);
        ThemeCtl(g_histList);
        hdr = ListView_GetHeader(g_histList);
        SetWindowSubclass(hdr, HeaderProc, 1, 0);
        SetPropW(hdr, L"ownsort", (HANDLE)1); SetPropW(hdr, L"scol", (HANDLE)(INT_PTR)(g_hSortCol + 1)); if (g_hSortAsc) SetPropW(hdr, L"sasc", (HANDLE)1); SetPropW(hdr, L"ralign", (HANDLE)(UINT_PTR)0x14);
        ZeroMemory(&col, sizeof col); col.mask = LVCF_TEXT | LVCF_WIDTH; col.cx = 100;
        for (int i = 0; i < HCOLS; i++) { col.pszText = (LPWSTR)names[i]; ListView_InsertColumn(g_histList, i, &col); }
        g_histEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 10, 10, h, (HMENU)IDC_H_EDIT, g_inst, NULL);
        SendMessageW(g_histEdit, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_histEdit, EM_SETCUEBANNER, TRUE, (LPARAM)L"Filter by name, path, command line or parent...");
        SetWindowTheme(g_histEdit, g_dark ? L"DarkMode_CFD" : L"CFD", NULL);
        g_hbRec = MakeChild(h, L"BUTTON", L"Recording", BS_OWNERDRAW, 0, 0, 10, 10, IDC_H_REC);
        g_hbShort = MakeChild(h, L"BUTTON", L"Short-lived", BS_OWNERDRAW, 0, 0, 10, 10, IDC_H_SHORT);
        g_hbWatch = MakeChild(h, L"BUTTON", L"Kill & Watch", BS_OWNERDRAW, 0, 0, 10, 10, IDC_H_WATCH);
        g_hbCopy = MakeChild(h, L"BUTTON", L"Copy", BS_OWNERDRAW, 0, 0, 10, 10, IDC_H_COPY);
        g_hbClear = MakeChild(h, L"BUTTON", L"Clear", BS_OWNERDRAW, 0, 0, 10, 10, IDC_H_CLEAR);
        FlatButton(g_hbRec); FlatButton(g_hbShort); FlatButton(g_hbWatch); FlatButton(g_hbCopy); FlatButton(g_hbClear);
        SetTimer(h, 1, 1000, NULL);
        return 0;
    }
    case WM_SIZE:
        HistLayout(h);
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)l)->ptMinTrackSize.x = MulDiv(980, (int)GetDpiForWindow(h), 96);
        ((MINMAXINFO *)l)->ptMinTrackSize.y = MulDiv(300, (int)GetDpiForWindow(h), 96);
        return 0;
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(h, &rc); FillRect((HDC)w, &rc, g_bgBrush);
        return 1;
    }
    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)w, cText); SetBkColor((HDC)w, cPanel);
        return (LRESULT)g_editBrush;
    case WM_TIMER:
        HistWndRefresh(FALSE);
        return 0;
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_NOTIFY: {
        NMHDR *nh = (NMHDR *)l;
        if (nh->hwndFrom != g_histList) break;
        if (nh->code == LVN_COLUMNCLICK) {
            int c = ((NMLISTVIEW *)l)->iSubItem; HWND hdr = ListView_GetHeader(g_histList);
            BOOL firstAsc = (c == 3 || c >= 5);
            if (c == g_hSortCol) { if (g_hSortAsc == firstAsc) g_hSortAsc = !g_hSortAsc; else { g_hSortCol = -1; g_hSortAsc = FALSE; } }   /* third click: back to the default */
            else { g_hSortCol = c; g_hSortAsc = (c == 3 || c >= 5); }      /* names A-Z, times and numbers newest / largest first */
            SetPropW(hdr, L"scol", (HANDLE)(INT_PTR)(g_hSortCol + 1));
            if (g_hSortAsc) SetPropW(hdr, L"sasc", (HANDLE)1); else RemovePropW(hdr, L"sasc");
            InvalidateRect(hdr, NULL, TRUE);
            HistWndRefresh(TRUE);
            return 0;
        }
        if (nh->code == LVN_GETDISPINFOW) {
            NMLVDISPINFOW *d = (NMLVDISPINFOW *)nh;
            if ((d->item.mask & LVIF_TEXT) && d->item.iItem >= 0 && d->item.iItem < g_nhsnap) HistRowText(&g_hsnap[d->item.iItem], d->item.iSubItem, d->item.pszText, d->item.cchTextMax);
            return 0;
        }
        if (nh->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)nh;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int i = (int)cd->nmcd.dwItemSpec; COLORREF c = cText;
                if (i >= 0 && i < g_nhsnap) {
                    const HistEntry *e = &g_hsnap[i];
                    if (!e->ended) c = cGreen;                                                    /* still running */
                    else if ((FtU64(&e->end) - FtU64(&e->start)) / 10000ull < 2000) c = cAmber;   /* came and went within 2 s */
                }
                cd->clrText = c;
                return CDRF_NEWFONT;
            }
        }
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_H_EDIT: if (HIWORD(w) == EN_CHANGE) HistWndRefresh(TRUE); break;
        case IDC_H_REC: HistToggleRecording(); break;
        case IDC_H_SHORT: g_hShort = !g_hShort; HistUiState(); HistWndRefresh(TRUE); break;
        case IDC_H_WATCH: HistWatchSelected(); break;
        case IDC_H_COPY: HistCopy(); break;
        case IDC_H_CLEAR:
            EnterCriticalSection(&g_hcs); g_nhist = 0; InterlockedIncrement(&g_histSeq); LeaveCriticalSection(&g_hcs);
            HistWndRefresh(TRUE);
            break;
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        KillTimer(h, 1);
        g_histWnd = NULL; g_histList = NULL; g_histEdit = NULL;
        free(g_hsnap); g_hsnap = NULL; g_nhsnap = 0; g_hsnapSeq = -1;
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static void ShowHistory(void)
{
    static BOOL registered; BOOL dark = g_dark; UINT dpi; RECT wa; int pref = 2;
    HistInitOnce();
    if (g_histWnd) { if (IsIconic(g_histWnd)) ShowWindow(g_histWnd, SW_RESTORE); SetForegroundWindow(g_histWnd); HistWndRefresh(TRUE); return; }
    if (!registered) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = HistProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSWPKHist"; wc.hIcon = g_iconBig;
        RegisterClassW(&wc); registered = TRUE;
    }
    dpi = GetDpiForWindow(g_hwnd); GetWindowRect(g_hwnd, &wa);
    g_histWnd = CreateWindowExW(0, L"SHSWPKHist", L"Process history", WS_OVERLAPPEDWINDOW,
                                wa.left + MulDiv(30, (int)dpi, 96), wa.top + MulDiv(30, (int)dpi, 96), MulDiv(1280, (int)dpi, 96), MulDiv(600, (int)dpi, 96), NULL, NULL, g_inst, NULL);
    if (!g_histWnd) return;
    if (g_iconSmall) SendMessageW(g_histWnd, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    if (g_iconBig) SendMessageW(g_histWnd, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    DwmSetWindowAttribute(g_histWnd, 20, &dark, sizeof dark);
    DwmSetWindowAttribute(g_histWnd, 33, &pref, sizeof pref);
    HistLayout(g_histWnd);
    HistUiState();
    HistWndRefresh(TRUE);
    ShowWindow(g_histWnd, SW_SHOW);
}

/* ---------- global shortcut that shows the window ---------- */
enum { IDC_K_SAVE = 721, IDC_K_CLEAR, IDC_K_CANCEL };
static HWND g_hkWnd, g_hkBSave, g_hkBClear, g_hkBCancel;
static UINT g_hkCandMods, g_hkCandVk;                    /* what the dialog is showing right now */

static void HotkeyText(UINT mods, UINT vk, wchar_t *o, size_t cap)
{
    o[0] = 0;
    if (mods & MOD_CONTROL) wcsncat(o, L"Ctrl+", cap - wcslen(o) - 1);
    if (mods & MOD_ALT) wcsncat(o, L"Alt+", cap - wcslen(o) - 1);
    if (mods & MOD_SHIFT) wcsncat(o, L"Shift+", cap - wcslen(o) - 1);
    if (mods & MOD_WIN) wcsncat(o, L"Win+", cap - wcslen(o) - 1);
    if (vk) {
        wchar_t k[40]; LONG lp = (LONG)(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC) << 16);
        if (vk == VK_INSERT || vk == VK_DELETE || vk == VK_HOME || vk == VK_END || vk == VK_PRIOR || vk == VK_NEXT ||
            vk == VK_LEFT || vk == VK_RIGHT || vk == VK_UP || vk == VK_DOWN || vk == VK_NUMLOCK || vk == VK_DIVIDE) lp |= 1L << 24;
        if (GetKeyNameTextW(lp, k, 40) <= 0) swprintf(k, 40, L"Key %u", vk);
        wcsncat(o, k, cap - wcslen(o) - 1);
    }
}

/* Register the shortcut (or remove it when vk is 0). FALSE = another program already uses it. */
static BOOL HotkeyApply(UINT mods, UINT vk)
{
    UnregisterHotKey(g_hwnd, HOTKEY_ID);
    if (!vk) return TRUE;
    return RegisterHotKey(g_hwnd, HOTKEY_ID, mods | MOD_NOREPEAT, vk);
}

static UINT HeldMods(void)
{
    UINT m = 0;
    if (GetKeyState(VK_CONTROL) & 0x8000) m |= MOD_CONTROL;
    if (GetKeyState(VK_MENU) & 0x8000) m |= MOD_ALT;
    if (GetKeyState(VK_SHIFT) & 0x8000) m |= MOD_SHIFT;
    if ((GetKeyState(VK_LWIN) & 0x8000) || (GetKeyState(VK_RWIN) & 0x8000)) m |= MOD_WIN;
    return m;
}

static LRESULT CALLBACK HotkeyProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE:
        g_hkWnd = h;
        g_hkBSave = MakeChild(h, L"BUTTON", L"Save", BS_OWNERDRAW, 0, 0, 10, 10, IDC_K_SAVE);
        g_hkBClear = MakeChild(h, L"BUTTON", L"Remove shortcut", BS_OWNERDRAW, 0, 0, 10, 10, IDC_K_CLEAR);
        g_hkBCancel = MakeChild(h, L"BUTTON", L"Cancel", BS_OWNERDRAW, 0, 0, 10, 10, IDC_K_CANCEL);
        FlatButton(g_hkBSave); FlatButton(g_hkBClear); FlatButton(g_hkBCancel);
        g_hkCandMods = g_hkMods; g_hkCandVk = g_hkVk;
        return 0;
    case WM_SIZE: {
        RECT rc; UINT dpi = GetDpiForWindow(h);
        int mg = MulDiv(16, (int)dpi, 96), bh = MulDiv(34, (int)dpi, 96), gap = MulDiv(8, (int)dpi, 96), bw = MulDiv(130, (int)dpi, 96), y, x;
        GetClientRect(h, &rc);
        y = rc.bottom - mg - bh; x = rc.right - mg - 3 * bw - 2 * gap;
        MoveWindow(g_hkBSave, x, y, bw, bh, TRUE); x += bw + gap;
        MoveWindow(g_hkBClear, x, y, bw, bh, TRUE); x += bw + gap;
        MoveWindow(g_hkBCancel, x, y, bw, bh, TRUE);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc, r, box; UINT dpi = GetDpiForWindow(h); wchar_t t[120];
        HGDIOBJ of; HBRUSH pb = CreateSolidBrush(cPanel); HPEN pen = CreatePen(PS_SOLID, 1, cLine);
        #define S(v) MulDiv((v), (int)dpi, 96)
        GetClientRect(h, &rc); FillRect(dc, &rc, g_bgBrush);
        SetBkMode(dc, TRANSPARENT);
        of = SelectObject(dc, g_font);
        SetTextColor(dc, cText);
        r = rc; r.left = S(16); r.right -= S(16); r.top = S(16); r.bottom = S(44);
        DrawTextW(dc, L"Press the keys you want to use to show this window:", -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT);
        box = rc; box.left = S(16); box.right -= S(16); box.top = S(52); box.bottom = S(104);
        SelectObject(dc, pb); SelectObject(dc, pen);
        RoundRect(dc, box.left, box.top, box.right, box.bottom, S(10), S(10));
        SelectObject(dc, g_fontBold ? g_fontBold : g_font);
        if (g_hkCandVk || g_hkCandMods) { HotkeyText(g_hkCandMods, g_hkCandVk, t, 100); if (!g_hkCandVk) wcscat(t, L"..."); SetTextColor(dc, cText); }
        else { wcscpy(t, L"(no shortcut set)"); SetTextColor(dc, cDim); }
        DrawTextW(dc, t, -1, &box, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
        SelectObject(dc, g_font);
        SetTextColor(dc, cDim);
        r = rc; r.left = S(16); r.right -= S(16); r.top = S(112); r.bottom = S(rc.bottom > 0 ? 150 : 150);
        DrawTextW(dc, L"Hold Ctrl, Alt, Shift or Win and press a key. It works from anywhere in Windows, even while this program is hidden in the notification area.", -1, &r, DT_WORDBREAK | DT_LEFT);
        SelectObject(dc, of);
        DeleteObject(pb); DeleteObject(pen);
        #undef S
        EndPaint(h, &ps);
        return 0;
    }
    case WM_KEYDOWN: case WM_SYSKEYDOWN: {
        UINT vk = (UINT)w, mods = HeldMods();
        if (vk == VK_ESCAPE && !mods) { DestroyWindow(h); return 0; }
        if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU || vk == VK_LWIN || vk == VK_RWIN) {
            g_hkCandMods = mods; g_hkCandVk = 0;               /* only modifiers so far */
        } else if (mods) {
            g_hkCandMods = mods; g_hkCandVk = vk;
        }
        InvalidateRect(h, NULL, FALSE);
        return 0;
    }
    case WM_KEYUP: case WM_SYSKEYUP:
        return 0;
    case WM_SYSCOMMAND:
        if ((w & 0xFFF0) == SC_KEYMENU) return 0;               /* Alt alone must not open a menu */
        break;
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_K_SAVE:
            if (!g_hkCandVk) { ShowDialog(h, APP_NAME, L"Hold Ctrl, Alt, Shift or Win and press a key first.", L"OK", NULL, NULL); }
            else if (HotkeyApply(g_hkCandMods, g_hkCandVk)) { g_hkMods = g_hkCandMods; g_hkVk = g_hkCandVk; SaveSettings(); DestroyWindow(h); return 0; }
            else {
                HotkeyApply(g_hkMods, g_hkVk);                  /* put the old one back */
                ShowDialog(h, APP_NAME, L"Another program already uses that shortcut. Please try a different one.", L"OK", NULL, NULL);
            }
            break;
        case IDC_K_CLEAR: HotkeyApply(0, 0); g_hkMods = 0; g_hkVk = 0; SaveSettings(); DestroyWindow(h); return 0;
        case IDC_K_CANCEL: DestroyWindow(h); return 0;
        }
        SetFocus(h);                                            /* so the next key press is captured here, not by a button */
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        g_hkWnd = NULL;
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static void ShowHotkeyDialog(void)
{
    static BOOL registered; BOOL dark = g_dark; UINT dpi; RECT wr; int pref = 2, W, H;
    if (g_hkWnd) { SetForegroundWindow(g_hkWnd); return; }
    if (!registered) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = HotkeyProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSWPKHotkey"; wc.hIcon = g_iconBig;
        RegisterClassW(&wc); registered = TRUE;
    }
    dpi = GetDpiForWindow(g_hwnd); GetWindowRect(g_hwnd, &wr);
    W = MulDiv(520, (int)dpi, 96); H = MulDiv(290, (int)dpi, 96);
    g_hkWnd = CreateWindowExW(WS_EX_DLGMODALFRAME, L"SHSWPKHotkey", L"Shortcut to show the window", WS_POPUP | WS_CAPTION | WS_SYSMENU,
                              wr.left + ((wr.right - wr.left) - W) / 2, wr.top + ((wr.bottom - wr.top) - H) / 2, W, H, g_hwnd, NULL, g_inst, NULL);
    if (!g_hkWnd) return;
    DwmSetWindowAttribute(g_hkWnd, 20, &dark, sizeof dark);
    DwmSetWindowAttribute(g_hkWnd, 33, &pref, sizeof pref);
    SendMessageW(g_hkWnd, WM_SIZE, 0, 0);
    ShowWindow(g_hkWnd, SW_SHOW);
    SetForegroundWindow(g_hkWnd);
    SetFocus(g_hkWnd);
}

static void RefreshIcons(UINT dpi)
{
    int sm = GetSystemMetricsForDpi(SM_CXSMICON, dpi);
    HICON ni = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, sm, sm, LR_DEFAULTCOLOR);
    if (ni) {
        HICON old = g_iconSmall, oldOff = g_iconSmallOff; g_iconSmall = ni; g_iconSmallOff = TintGray(ni);
        SendMessageW(g_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)ni);
        UpdateTray();
        if (old) DestroyIcon(old);
        if (oldOff) DestroyIcon(oldOff);
    }
}

static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE:
        g_hwnd = h;
        CreateControls(h);
        return 0;
    case WM_DPICHANGED: {
        const RECT *r = (const RECT *)l;
        HWND hdr = ListView_GetHeader(g_list);
        SetWindowPos(h, NULL, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        CreateFonts(HIWORD(w));
        RefreshIcons(HIWORD(w));
        { HWND c[] = {g_search, g_list, hdr, g_bToggle, g_bWatch, g_bKill, g_bAdd, g_bNotify, g_bOptions, g_status};
          for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) if (c[i]) SendMessageW(c[i], WM_SETFONT, (WPARAM)g_font, TRUE); }
        SetWindowPos(g_list, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        Layout();
        RedrawWindow(h, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
        return 0;
    }
    case WM_SIZE:
        if (w == SIZE_MINIMIZED && g_minTray) { ShowWindow(h, SW_HIDE); return 0; }
        if (w == SIZE_MINIMIZED) { TrimMemory(); return 0; }
        Layout();
        if (g_refreshPending) { g_refreshPending = FALSE; RefreshNow(); }
        return 0;
    case WM_SHOWWINDOW:
        if (w) { if (g_refreshPending) { g_refreshPending = FALSE; RefreshNow(); } }
        else TrimMemory();
        break;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)l)->ptMinTrackSize.x = MulDiv(1000, (int)GetDpiForWindow(h), 96);
        ((MINMAXINFO *)l)->ptMinTrackSize.y = MulDiv(360, (int)GetDpiForWindow(h), 96);
        return 0;
    case WM_MEASUREITEM: {
        MEASUREITEMSTRUCT *mi = (MEASUREITEMSTRUCT *)l;
        if (mi->CtlType == ODT_LISTVIEW) { mi->itemHeight = (UINT)MulDiv(26, (int)GetDpiForWindow(h), 96); return TRUE; }
        break;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *di = (DRAWITEMSTRUCT *)l;
        if (di->CtlType == ODT_BUTTON) { DrawFlatButton(di); return TRUE; }
        if (di->CtlType == ODT_LISTVIEW) { DrawListRow(di); return TRUE; }
        if (di->CtlID == IDC_STATUS) { DrawStatusBar(di); return TRUE; }
        break;
    }
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(h, &rc); FillRect((HDC)w, &rc, g_bgBrush);
        if (g_searchBox.right > 0) FillRounded((HDC)w, &g_searchBox, MulDiv(8, (int)GetDpiForWindow(h), 96), cPanel);
        if (g_sepX > 0) {
            HPEN pen = CreatePen(PS_SOLID, 1, COL_LINE); HGDIOBJ op = SelectObject((HDC)w, pen);
            MoveToEx((HDC)w, g_sepX, g_sepY0, NULL); LineTo((HDC)w, g_sepX, g_sepY1);
            SelectObject((HDC)w, op); DeleteObject(pen);
        }
        return 1;
    }
    case WM_CTLCOLORSTATIC:
        SetTextColor((HDC)w, (HWND)l == g_status ? COL_DIM : COL_TEXT);
        SetBkColor((HDC)w, (HWND)l == g_status ? COL_PANEL : COL_BG);
        return (LRESULT)((HWND)l == g_status ? g_editBrush : g_bgBrush);
    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)w, COL_TEXT); SetBkColor((HDC)w, COL_PANEL);
        return (LRESULT)g_editBrush;
    case WM_NOTIFY:
        return OnNotify((NMHDR *)l);
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_TOGGLE: case IDT_MONITOR: ToggleMonitor(); break;
        case IDC_WATCH: ToggleSelected(); break;
        case IDM_ROW_WATCH: { const Item *it = SelectedItem(); if (it) WatchItem(it); break; }
        case IDM_ROW_UNWATCH: { const Item *it = SelectedItem(); if (it) UnwatchItem(it); break; }
        case IDC_KILL: case IDM_ROW_KILL: { const Item *it = SelectedItem(); if (it) KillOnce(it); break; }
        case IDM_LOCATION: { const Item *it = SelectedItem(); if (it) OpenLocation(it); break; }
        case IDM_COPYNAME: { const Item *it = SelectedItem(); if (it) CopyToClipboard(h, it->kind == K_SVC ? it->id : it->name); break; }
        case IDC_ADD: AddProgram(); break;
        case IDC_NOTIFY: case IDT_NOTIFY: g_notify = !g_notify; SaveSettings(); RefreshStatus(); break;
        case IDC_OPTIONS: ShowOptionsMenu(); break;
        case IDC_SEARCH: if (HIWORD(w) == EN_CHANGE) RebuildView(); break;
        case IDM_AUTOSTART:
            if (!SetAutostart(g_autoCache <= 0)) ShowDialog(h, APP_NAME, L"Could not change the Windows startup entry (this needs administrator rights and the Task Scheduler service).", L"OK", NULL, NULL);
            AutostartEnabled();
            break;
        case IDM_STARTMIN: g_startMin = !g_startMin; SaveSettings(); break;
        case IDM_AUTOMON: g_autoMon = !g_autoMon; SaveSettings(); break;
        case IDM_CLOSETRAY: g_closeTray = !g_closeTray; SaveSettings(); break;
        case IDM_MINTRAY: g_minTray = !g_minTray; SaveSettings(); break;
        case IDM_ONTOP: g_onTop = !g_onTop; SaveSettings(); ApplyOnTop(); break;
        case IDM_ONLYRUN: g_onlyRun = !g_onlyRun; SaveSettings(); RebuildView(); break;
        case IDM_SHOWPROC: g_showProc = !g_showProc; SaveSettings(); RebuildView(); break;
        case IDM_SHOWSVC: g_showSvc = !g_showSvc; SaveSettings(); RebuildView(); break;
        case IDT_SHOW: if (IsWindowVisible(h)) ShowWindow(h, SW_HIDE); else ShowMain(); break;
        case IDT_EXIT: QuitApp(); break;
        case IDM_THEME_DARK: g_theme = 0; SaveSettings(); ApplyTheme(); break;
        case IDM_THEME_LIGHT: g_theme = 1; SaveSettings(); ApplyTheme(); break;
        case IDM_THEME_SYSTEM: g_theme = 2; SaveSettings(); ApplyTheme(); break;
        case IDM_HL_WATCHED: g_hl ^= HL_WATCHED; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_HL_SYSTEM: g_hl ^= HL_SYSTEM; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_REFRESH: RefreshApps(); break;
        case IDM_KILLLOG: ShowKillLog(); break;
        case IDM_HISTORY: ShowHistory(); break;
        case IDM_HOTKEY: ShowHotkeyDialog(); break;
        case IDM_HISTREC: HistToggleRecording(); break;
        case IDM_FOLDER: ShellExecuteW(h, L"open", g_dataDir, NULL, NULL, SW_SHOWNORMAL); break;
        case IDM_ABOUT: ShowAbout(); break;
        case IDM_OPENLOG:
            if (GetFileAttributesW(g_logFile) == INVALID_FILE_ATTRIBUTES) Log(L"(log opened by user)");
            ShellExecuteW(h, L"open", g_logFile, NULL, NULL, SW_SHOWNORMAL);
            break;
        }
        return 0;
    case WM_APP_KILLED: {
        wchar_t *txt = (wchar_t *)l;
        if (txt) { if (g_notify) Balloon(txt); free(txt); }
        RefreshApps();
        LogWndRefresh();
        return 0;
    }
    case WM_TRAY:
        if (LOWORD(l) == WM_LBUTTONUP || LOWORD(l) == WM_LBUTTONDBLCLK) {
            if (IsWindowVisible(h) && !IsIconic(h)) ShowWindow(h, SW_HIDE); else ShowMain();
        } else if (LOWORD(l) == WM_RBUTTONUP || LOWORD(l) == WM_CONTEXTMENU) ShowTrayMenu();
        return 0;
    case WM_TIMER:
        if (w == TIMER_TRAY) {
            if (g_trayOk || ++g_trayTries > 40) KillTimer(h, TIMER_TRAY);
            else { AddTray(); if (g_trayOk) UpdateTray(); }
        }
        if (w == TIMER_REFRESH && !WindowIdle() && !g_menuOpen) {                 /* new processes show up on their own */
            static int skip; DWORD fgPid = 0; HWND fg = GetForegroundWindow();
            if (fg) GetWindowThreadProcessId(fg, &fgPid);
            if (fgPid != GetCurrentProcessId() && ++skip < 3) return 0;          /* in the background: refresh only every third tick (6 s) */
            skip = 0;
            RefreshNow();
        }
        return 0;
    case WM_SETTINGCHANGE:
        if (l && wcscmp((LPCWSTR)l, L"ImmersiveColorSet") == 0 && g_theme == 2) ApplyTheme();
        break;
    case WM_ENDSESSION:
        if (w) SaveWindowPos();
        break;
    case WM_HOTKEY:
        if (w == HOTKEY_ID) {
            if (IsWindowVisible(h) && !IsIconic(h) && GetForegroundWindow() == h) ShowWindow(h, SW_HIDE); else ShowMain();
        }
        return 0;
    case WM_SHOWME:
        ShowMain();
        return 0;
    case WM_CLOSE:
        if (!g_quit && g_closeTray) { SaveWindowPos(); ShowWindow(h, SW_HIDE); return 0; }
        QuitApp();
        return 0;
    case WM_DESTROY:
        if (g_logWnd) DestroyWindow(g_logWnd);
        if (g_histWnd) DestroyWindow(g_histWnd);
        KillTimer(h, TIMER_REFRESH);
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        g_hwnd = NULL;
        PostQuitMessage(0);
        return 0;
    }
    if (g_taskbarCreated && m == g_taskbarCreated) { AddTray(); UpdateTray(); return 0; }
    return DefWindowProcW(h, m, w, l);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */
int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmd, int show)
{
    WNDCLASSW wc; MSG msg; HANDLE mutex;
    (void)prev;
    g_inst = inst;
    InitializeCriticalSection(&g_cs);
    InitPaths();
    LogInit(cmd);

    mutex = CreateMutexW(NULL, TRUE, L"Local\\SailHighSeaWinProcessKiller");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND other = FindWindowW(L"SHSWPKMain", NULL);
        if (other) PostMessageW(other, WM_SHOWME, 0, 0);
        return 0;
    }

    { INITCOMMONCONTROLSEX ic = {sizeof ic, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES}; InitCommonControlsEx(&ic); }
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    EnableDebugPriv();

    GetWindowsDirectoryW(g_winDir, MAX_PATH);
    { SYSTEM_INFO si; GetSystemInfo(&si); g_ncpu = si.dwNumberOfProcessors ? (int)si.dwNumberOfProcessors : 1; }
    g_taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    g_iconBig = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
    g_iconSmall = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
    g_iconSmallOff = TintGray(g_iconSmall);
    LoadSettings();
    LoadRules();
    g_paused = (!g_autoMon || (cmd && (wcsstr(cmd, L"--no-monitor") || wcsstr(cmd, L"--paused")))) ? 1 : 0;
    Log(L"Loaded %d watch-list entr%ls; theme=%d monitoring=%ls", g_nrules, g_nrules == 1 ? L"y" : L"ies", g_theme, g_paused ? L"paused" : L"on");

    StartGdip();
    ApplyTheme();   /* colours + brushes (window does not exist yet) */
    if (AutostartEnabled()) {
        wchar_t target[MAX_PATH], me[MAX_PATH];
        GetModuleFileNameW(NULL, me, MAX_PATH);
        if (AutostartTarget(target, MAX_PATH) && _wcsicmp(target, me) != 0 && GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES) {
            BOOL fixed = SetAutostart(TRUE);       /* the old copy was moved or deleted: repoint the task here */
            Log(L"Start with Windows: task pointed to a missing file (%ls); repointed -> %ls", BaseName(target), fixed ? L"ok" : L"FAILED");
        }
    }

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = MainProc; wc.hInstance = inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszClassName = L"SHSWPKMain";
    wc.hIcon = g_iconBig ? g_iconBig : LoadIcon(NULL, IDI_SHIELD);
    RegisterClassW(&wc);

    {
        int x = CW_USEDEFAULT, y = CW_USEDEFAULT, w = 1100, h = 640;
        int sw = GetPrivateProfileIntW(L"window", L"w", 0, g_iniFile), sh = GetPrivateProfileIntW(L"window", L"h", 0, g_iniFile);
        int sx = GetPrivateProfileIntW(L"window", L"x", 0, g_iniFile), sy = GetPrivateProfileIntW(L"window", L"y", 0, g_iniFile);
        RECT saved = {sx, sy, sx + sw, sy + sh};
        if (sw >= 600 && sh >= 300 && sw < 20000 && sh < 20000 && MonitorFromRect(&saved, MONITOR_DEFAULTTONULL)) {
            x = sx; y = sy; w = sw; h = sh;
        } else if (sw >= 600 && sh >= 300 && sw < 20000 && sh < 20000) { w = sw; h = sh; }
        g_wantMax = GetPrivateProfileIntW(L"window", L"max", 0, g_iniFile) != 0;
        g_hwnd = CreateWindowExW(0, L"SHSWPKMain", APP_NAME L"  v" APP_VERSION, WS_OVERLAPPEDWINDOW, x, y, w, h, NULL, NULL, inst, NULL);
    }
    if (!g_hwnd) return 1;
    ApplyTheme();
    if (g_iconBig) SendMessageW(g_hwnd, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    if (g_iconSmall) SendMessageW(g_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    AddTray();
    SetTimer(g_hwnd, TIMER_REFRESH, 2000, NULL);
    if (g_onTop) ApplyOnTop();
    StartMonitorThread();
    if (g_hkVk && !HotkeyApply(g_hkMods, g_hkVk)) Log(L"Show-window shortcut is already used by another program");
    if (g_histRec) { ULONG hr = StartHistory(); if (hr) { g_histRec = FALSE; SaveSettings(); } }
    if (g_startMin || (cmd && wcsstr(cmd, L"--minimized"))) ShowWindow(g_hwnd, SW_HIDE); else { ShowWindow(g_hwnd, g_wantMax ? SW_SHOWMAXIMIZED : show); g_wantMax = FALSE; }
    UpdateWindow(g_hwnd);
    Layout();
    RefreshApps();

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_F5 && g_hwnd && GetAncestor(msg.hwnd, GA_ROOT) == g_hwnd) {
            SendMessageW(g_hwnd, WM_COMMAND, IDM_REFRESH, 0); continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    StopMonitorThread();
    StopHistory();
    Log(L"Exited normally");
    if (mutex) CloseHandle(mutex);
    return (int)msg.wParam;
}
