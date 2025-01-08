use clap::{CommandFactory, Parser, Subcommand};
use reedline::{DefaultCompleter, Prompt, PromptEditMode, PromptHistorySearch};
use reedline::{Reedline, Signal};
use std::borrow::Cow;
use std::process;
use std::thread;
use tokio::sync::mpsc::{self, Receiver, Sender};

struct InputPrompt {
    prompt: String,
}

impl InputPrompt {
    fn new(prompt: &str) -> Self {
        Self {
            prompt: prompt.to_string(),
        }
    }
}

impl Prompt for InputPrompt {
    fn render_prompt_left(&self) -> Cow<str> {
        self.prompt.as_str().into()
    }

    fn render_prompt_right(&self) -> Cow<str> {
        "".into()
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<str> {
        "» ".into()
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<str> {
        "::: ".into()
    }

    fn render_prompt_history_search_indicator(
        &self,
        _history_search: PromptHistorySearch,
    ) -> Cow<str> {
        "(search) ». ".into()
    }
}

pub struct InputLoop {
    prompt: String,
    commands: Vec<String>,
    buffer_size: usize,
    sender: Option<Sender<String>>,
    receiver: Option<Receiver<String>>,
}

impl InputLoop {
    pub fn new(prompt: String, commands: Vec<String>, buffer_size: usize) -> Self {
        Self {
            prompt,
            commands,
            buffer_size,
            sender: None,
            receiver: None,
        }
    }

    pub fn run(&mut self) {
        // Setup channels for communication
        let (input_sender, main_receiver) = mpsc::channel::<String>(self.buffer_size);
        let (main_sender, mut input_receiver) = mpsc::channel::<String>(self.buffer_size);

        let commands = self.commands.clone();
        let prompt = self.prompt.to_string();

        // Start input thread
        thread::spawn(move || {
            let completer = Box::new(DefaultCompleter::new(commands));

            // Create the Reedline editor with the completer
            let mut editor = Reedline::create()
                .with_completer(completer)
                .with_quick_completions(true)
                .with_partial_completions(true);

            let prompt = InputPrompt::new(prompt.as_str());
            loop {
                match editor.read_line(&prompt) {
                    Ok(Signal::Success(line)) => {
                        if line.is_empty() {
                            continue;
                        }

                        if line.trim().to_lowercase() == "exit" {
                            println!("Exiting...");
                            input_sender
                                .try_send("exit".to_string())
                                .expect("Unable to send quit command");
                            break;
                        }

                        if input_sender.try_send(line).is_err() {
                            println!("Failed to send input");
                        }
                    }
                    Ok(Signal::CtrlC) | Ok(Signal::CtrlD) => {
                        println!("Exiting...");
                        input_sender
                            .try_send("quit".to_string())
                            .expect("Unable to send quit command");
                        break;
                    }
                    Err(err) => {
                        println!("Error reading line: {}", err);
                    }
                }

                let command_result = input_receiver
                    .blocking_recv()
                    .expect("Failed to receive input");
                println!("{}", command_result);
            }
        });

        self.sender = Some(main_sender);
        self.receiver = Some(main_receiver);
    }

    pub fn read(&mut self) -> Option<Vec<String>> {
        match self.receiver {
            Some(ref mut receiver) => {
                if let Ok(input) = receiver.try_recv() {
                    let mut args = vec!["input"];
                    args.extend(input.split_whitespace());
                    Some(args.into_iter().map(String::from).collect())
                } else {
                    None
                }
            }
            None => None,
        }
    }

    pub fn write(&self, data: &str) {
        match self.sender {
            Some(ref sender) => {
                sender
                    .try_send(data.to_string())
                    .expect("Failed to send message");
            }
            None => {}
        }
    }
}
