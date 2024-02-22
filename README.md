# invariant-gpt

Simple script to use ChatGPT to generate invariants from audit findings.

Forked from [chatgpt-retrieval](https://github.com/techleadhd/chatgpt-retrieval)
Accompanying YouTube video for the original repo [YouTube Video](https://youtu.be/9AXP7tCI9PI).

## Installation

Install [Langchain](https://github.com/hwchase17/langchain) and other required packages.
```
pip install langchain openai chromadb tiktoken unstructured
```
Modify `constants.py.default` to use your own [OpenAI API key](https://platform.openai.com/account/api-keys), and rename it to `constants.py`.

Training data can be added into `data/` directory as long as the file format is supported by `unstructured` handler.

## Example Usage
Test reading `data/data.txt` file.
```
> python chatgpt.py "what are the different types of properties that certora defines"
Certora defines 5 main types of properties:

1. Valid States
2. State Transitions
3. Variable Transitions
4. High-Level Properties
5. Unit Tests
```

To quit a chat session use the keyword q | quit | exit + enter.

To save chat history for better responses enable PERSIST=true. This requires adding a Chromadb instance for saving VectorStores.
