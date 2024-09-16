import json
from random_word import RandomWords
from tqdm import tqdm
import concurrent.futures
import threading

# Shared set to store unique words across all threads
word_set = set()
word_set_lock = threading.Lock()

# Shared counter for progress tracking
progress_counter = 0
progress_lock = threading.Lock()

def generate_words(num_words, pbar):
    r = RandomWords()
    local_words = set()
    global progress_counter

    attempts = 0
    max_attempts = num_words * 100

    while len(local_words) < num_words and attempts < max_attempts:
        word = r.get_random_word()
        if word and 1 <= len(word) <= 5:  # Changed from 4 to 5
            local_words.add(word.lower())
            with progress_lock:
                progress_counter += 1
                pbar.update(1)
        attempts += 1

    # Add local words to shared set
    with word_set_lock:
        word_set.update(local_words)

def generate_word_list(num_words=1000, num_threads=10):
    words_per_thread = num_words // num_threads
    extra_words = num_words % num_threads

    print(f"Generating {num_words} unique words of 5 letters or less using {num_threads} threads...")
    
    with tqdm(total=num_words, unit="word") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for i in range(num_threads):
                words_for_this_thread = words_per_thread + (1 if i < extra_words else 0)
                futures.append(executor.submit(generate_words, words_for_this_thread, pbar))

            # Wait for all threads to complete
            concurrent.futures.wait(futures)

    word_list = list(word_set)
    print(f"\nGenerated {len(word_list)} unique words of 5 letters or less.")
    
    if len(word_list) < num_words:
        print(f"Warning: Could only generate {len(word_list)} unique words.")
    
    with open('word_list.json', 'w') as f:
        json.dump(word_list, f)
    
    print("Word list saved to word_list.json")
    print(f"First 10 words: {word_list[:10]}")

if __name__ == "__main__":
    generate_word_list(num_words=1000, num_threads=10)