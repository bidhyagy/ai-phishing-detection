import pickle

with open("vectorizer.pkl", "rb") as f:
    data = pickle.load(f)

# Print the type and structure of the loaded object
print("Type of data:", type(data))

if isinstance(data, dict):
    print("Keys found in dictionary:", data.keys())
elif isinstance(data, list):
    print("It is a list of length:", len(data))
    print("First few items:", data[:10])
else:
    # Print available attributes/methods to see what it is
    print("Available attributes:", dir(data))