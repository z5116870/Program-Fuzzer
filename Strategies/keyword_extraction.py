import json
import random

def keyword_extract(data, delimiter):
    dictionary = []
    file_data = []
    for line in data:
        dictionary += line.strip().split(delimiter)
        file_data += line.split(delimiter)

    return dictionary, file_data

def json_keyword_extract(data):
    return list(data.keys())

def json_mutate_input(data, dictionary):
    random_keyword = dictionary[random.randint(0, len(dictionary)-1)]
    random_json_location = random.randint(0, len(list(data.keys()))-1)
    random_json_keyword = ""
    i = 0
    for key in data.keys():
        if i == random_json_location:
            random_json_keyword = key;
        i += 1
    while (random_keyword == random_json_keyword):
        random_json_location = random.randint(0, len(list(data.keys()))-1)
        i = 0
        for key in data.keys():
            if i == random_json_location:
                random_json_keyword = key;
            i += 1

    random_keyword_value = data[random_keyword]
    random_json_keyword_value = data[random_json_keyword];

    # replace random_json_keyword with random_keyword
    data.pop(random_keyword)
    data.pop(random_json_keyword)

    data[random_keyword] = random_json_keyword_value;
    data[random_json_keyword] = random_keyword_value;

    return json.dumps(data)

def csv_keyword_extract(data):
    return keyword_extract(data, ",")

def csv_mutate_input(data, dictionary):
    random_keyword_index = random.randint(0, len(dictionary)-1)
    random_csv_keyword_index = random.randint(0, len(data)-1)

    words_to_replace = random.randint(0, len(data) -1)
    for i in range(0, words_to_replace):
        if ("\n" in data[random_csv_keyword_index]):
            data[random_csv_keyword_index] = dictionary[random_keyword_index] + "\n"
        else:
            data[random_csv_keyword_index] = dictionary[random_keyword_index]

        random_keyword_index = random.randint(0, len(dictionary)-1)
        random_csv_keyword_index = random.randint(0, len(data)-1)

    new_output = ""
    for word in data:
        if (new_output != "" and new_output[-1] == "\n") or new_output == "":
            new_output += word
        else:
            new_output += ("," + word)
    return new_output

def keyword_fuzzing(input, type = None, mutations = None):
    mutation_str = mutations
    if mutations is None:
        mutation_str = "random"
    # print("Fuzzing file:", input, "with type", type, "Number of keyword swaps:", mutation_str, "\n")

    file = open(input)
    fuzzed_output = ""
    if type == 'json':
        data = json.load(file)
        dictionary = json_keyword_extract(data)
        fuzzed_output = json_mutate_input(data, dictionary)
    elif type == 'csv':
        dictionary, file_data = csv_keyword_extract(file)
        fuzzed_output = csv_mutate_input(file_data, dictionary)
    else:
        # print("Type not supported or is none, output is not fuzzed")
        for line in file:
            fuzzed_output += line
    file.close()
    # print(fuzzed_output)
    return fuzzed_output

# if __name__ == "__main__":
    # keyword_fuzzing("assignment/csv1.txt", "csv")
    # keyword_fuzzing("assignment/json1.txt", "json")
    # keyword_fuzzing("assignment/plaintext1.txt", "")
