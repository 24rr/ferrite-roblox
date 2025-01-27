use anyhow::Result;
use clap::Parser;
use env_logger::Env;
use log::{error, info};

mod dumper;
mod pe;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    
    #[arg(short, long)]
    process: String,

    
    #[arg(short = 'd', long = "output-dir", required = true)]
    output: String,

    
    #[arg(short = 't', long = "threshold", default_value = "0.5")]
    threshold: f32,

    
    #[arg(short, long)]
    resolve_imports: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if !(0.0..=1.0).contains(&args.threshold) {
        error!("Threshold must be between 0.0 and 1.0");
        std::process::exit(1);
    }

    info!("Starting Ferrite PE dumper...");
    info!("Target process: {}", args.process);

    let dumper = dumper::Dumper::new(
        &args.process,
        args.threshold,
        args.resolve_imports,
        Some(args.output),
    )?;

    dumper.dump()?;

    Ok(())
}
