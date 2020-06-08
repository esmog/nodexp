from textgenrnn import textgenrnn

textgen = textgenrnn()
textgen.train_from_file('payloads.txt', num_epochs=100)
textgen.generate_to_file('new_payloads.txt', n=200, temperature=1.0)
