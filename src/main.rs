use crate::widgets::{
    packet_crafter::PacketCrafter, packet_sniffer::PacketSniffer, port_scanner::PortScanner,
};
use eframe::egui;

mod crafter;
mod scanner;
mod sniffer;
mod utils;
mod widgets;

#[derive(Default)]
struct DeepNetApp {
    port_scanner: PortScanner,
    packet_crafter: PacketCrafter,
    packet_sniffer: PacketSniffer,
    active_tab: Tab,
}

#[derive(PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Scanner,
    Crafter,
    Sniffer,
}

impl DeepNetApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Configure style and visuals
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals.dark_mode = true;
        style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(20, 20, 30);
        cc.egui_ctx.set_style(style);

        Self::default()
    }
}

impl eframe::App for DeepNetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("DeepNet - Advanced Network Toolkit");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label("v0.1.0");
                });
            });
        });

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::Scanner, "Port Scanner");
                ui.selectable_value(&mut self.active_tab, Tab::Crafter, "Packet Crafter");
                ui.selectable_value(&mut self.active_tab, Tab::Sniffer, "Packet Sniffer");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.active_tab {
            Tab::Scanner => self.port_scanner.ui(ui),
            Tab::Crafter => self.packet_crafter.ui(ui),
            Tab::Sniffer => self.packet_sniffer.ui(ui),
        });

        // Update sniffers and scanners in the background
        ctx.request_repaint();
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(1200.0, 800.0)),
        vsync: false,
        ..Default::default()
    };

    eframe::run_native(
        "DeepNet - Advanced Network Toolkit",
        options,
        Box::new(|cc| Box::new(DeepNetApp::new(cc))),
    )
}
