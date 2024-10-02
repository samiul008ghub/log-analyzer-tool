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

![Start Prompt](images/start_prompt.png)

### Step 2: Log Analysis Summary
Once the analysis completes, a summary of detected attack types is shown:

![Analysis Summary](images/analysis_summary.png)

### Step 3: Output Files
The results will be written to CSV and TXT files:

![Output Files](images/output_files.png)

