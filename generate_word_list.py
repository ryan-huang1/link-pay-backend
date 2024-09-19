import nltk
from nltk.corpus import brown
import random
import sys
import json
from tqdm import tqdm
from collections import Counter

def download_nltk_resources():
    """
    Downloads necessary NLTK resources if they are not already present.
    """
    required_corpora = ['brown', 'wordnet', 'punkt']
    for corpus in required_corpora:
        try:
            nltk.data.find(f'corpora/{corpus}')
        except LookupError:
            print(f"Downloading NLTK '{corpus}' corpus...")
            nltk.download(corpus)

def get_word_frequencies():
    """
    Retrieves word frequencies from the Brown corpus.
    Returns a Counter object with word frequencies.
    """
    print("Building word frequency distribution from the Brown corpus...")
    words = brown.words()
    # Convert words to lowercase and filter out non-alphabetic words
    words = [word.lower() for word in words if word.isalpha()]
    frequency = Counter(words)
    return frequency

def get_four_letter_common_words(frequency, min_frequency=5):
    """
    Extracts four-letter words from the frequency distribution.
    Filters out words below a certain frequency threshold to ensure commonality.
    """
    print("Filtering four-letter common words...")
    four_letter_words = [
        word for word in frequency
        if len(word) == 4 and frequency[word] >= min_frequency
    ]
    return four_letter_words

def select_top_n_words(four_letter_words, frequency, target_count=10000):
    """
    Selects the top N four-letter words based on frequency.
    If fewer than N words are available, returns all.
    """
    print(f"Selecting top {target_count} four-letter words based on frequency...")
    # Sort words by frequency in descending order
    sorted_words = sorted(
        four_letter_words,
        key=lambda w: frequency[w],
        reverse=True
    )
    # Select up to target_count words
    selected = sorted_words[:target_count]
    if len(selected) < target_count:
        print(f"Only {len(selected)} four-letter common words found.")
    return selected

def main():
    """
    Main function to execute the script steps:
    1. Download NLTK resources.
    2. Build word frequency distribution.
    3. Filter four-letter common words.
    4. Select top N words.
    5. Save to JSON file.
    """
    download_nltk_resources()
    frequency = get_word_frequencies()
    four_letter_words = get_four_letter_common_words(frequency, min_frequency=5)
    
    if not four_letter_words:
        print("No four-letter words found with the specified criteria.")
        sys.exit(1)
    
    selected_words = select_top_n_words(four_letter_words, frequency, target_count=10000)
    
    # Shuffle the selected words to add variety
    random.shuffle(selected_words)
    
    # Write the words to a JSON file
    output_file = "word_list.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(selected_words, f, indent=4)
        print(f"{len(selected_words)} four-letter common words have been written to '{output_file}'.")
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
