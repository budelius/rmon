//! System tray icon: lets rMon keep sampling in the background when the
//! main window is closed, and brings the window back via the tray menu or
//! a left click on the icon.

use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

pub enum TrayAction {
    Show,
    Quit,
}

pub struct Tray {
    _icon: TrayIcon, // kept alive: dropping this removes the tray icon
    show_id: MenuId,
    quit_id: MenuId,
}

impl Tray {
    pub fn new() -> anyhow::Result<Self> {
        let icon = Icon::from_rgba(crate::icon::rgba(32), 32, 32)?;

        let menu = Menu::new();
        let show = MenuItem::new("Show rMon", true, None);
        let quit = MenuItem::new("Quit", true, None);
        menu.append(&show)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&quit)?;

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(icon)
            .with_tooltip("rMon")
            .build()?;

        Ok(Self {
            _icon: icon,
            show_id: show.id().clone(),
            quit_id: quit.id().clone(),
        })
    }

    /// Polls the tray menu and tray-icon-click event channels; returns the
    /// first action to react to this frame, if any.
    pub fn poll(&self) -> Option<TrayAction> {
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.show_id {
                return Some(TrayAction::Show);
            }
            if event.id == self.quit_id {
                return Some(TrayAction::Quit);
            }
        }
        if let Ok(TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        }) = TrayIconEvent::receiver().try_recv()
        {
            return Some(TrayAction::Show);
        }
        None
    }
}
