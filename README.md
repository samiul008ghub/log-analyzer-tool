# Log Analyzer Tool

## Insights
Sometimes, web servers receive several suspicious requests that may not make sense. If you have a log file, such as an access.log or something similar, containing these entries, this tool can help by checking the requests against known malicious patterns using regular expressions.

The tool was created to address this challenge, allowing users to analyze log files and detect potential attack patterns like SQL Injection, Cross-Site Scripting (XSS), Remote File Inclusion (RFI), and more. However, users can also input their own custom regex patterns to search for specific attacks or behaviors, making it highly flexible for various security analysis tasks.

By running the tool, you can quickly identify suspicious requests and categorize them based on known attack patterns, providing valuable insights into possible threats.

## Features
- Detects various attack types such as SQL Injection, XSS, Remote File Inclusion, etc.
- Customizable with user-defined regex patterns.
- Outputs the results in CSV and TXT format.
- Provides a summary on the terminal.

## Usage

- Run the script using Python 3.
- Install required packages (e.g., `colorama`) automatically.
- Input a log file and choose built-in or custom patterns for analysis.

### Step 1: Start the Tool
After running the script, you will see the following prompt:

![Start Prompt](https://github.com/user-attachments/assets/ed24d075-d2db-42f3-9cd4-afa1db3d5c85)

### Step 2: Input your log file name

You need to type the name of your log file in the prompt. In my test lab I have used a file named input_log.csv (this is just a sample input log file)
Feel free to try with any log file as input which may have weird-looking web requests. 

![image](https://github.com/user-attachments/assets/7e964d40-90e4-47eb-b8ed-ac97fdcb4083)

### Note:
If the input log file is not being properly analyzed, it may be due to differences in line endings (e.g., Windows files using `\r\n` instead of Unix-style `\n`). To resolve this, you can use the `dos2unix` command to convert the log file:

```bash
dos2unix <your-log-file>
```
### Step 3: Log Analysis with the built-in regex expression of known common attack patterns or your's choice of regular expression
Select your option
![image](https://github.com/user-attachments/assets/017dbf6e-d907-49cd-9b3a-bb00c6547e56)


### Step 3: Log Analysis Summary
Once the analysis completes, a summary of detected attack types is shown:

![image](https://github.com/user-attachments/assets/efae3df2-64f0-482d-b9b3-567ea9ccdeee)



### Step 4: Output Files
The results will be written to CSV and TXT files:

![image](https://github.com/user-attachments/assets/54ad6f1f-e40d-4bdd-a057-fc21c81bc99e)

![image](https://github.com/user-attachments/assets/2ff1080f-fcde-4a67-b64e-888418124a34)

![image](https://github.com/user-attachments/assets/edbf8754-7b71-4988-96cf-042e459fd4d4)




