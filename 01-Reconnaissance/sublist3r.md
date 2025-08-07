Subdomain enumeration  In this guide, we explain the command:

  
```bash

./sublist3r.py -d acmeitsupport.thm

```

  
**Explanation of the Command:**

  
- `./sublist3r.py`: This executes the Sublist3r script located in the current directory.

- `-d acmeitsupport.thm`: The `-d` flag specifies the target domain for subdomain enumeration. In this case, the domain is `acmeitsupport.thm`.

  

**Purpose:** This command will trigger Sublist3r to begin searching for subdomains related to `acmeitsupport.thm` using various search engines and services. The output will list all the discovered subdomains, which can then be used for further analysis or testing.

  
**Other Useful Flags:**

  
- `-b`: Enable brute-force mode to discover subdomains by trying common prefixes.

    - Example:

        ```

        ./sublist3r.py -d acmeitsupport.thm -b

        ```

- `-v`: Enable verbose mode for more detailed output during the enumeration process.

    - Example:

        ```

        ./sublist3r.py -d acmeitsupport.thm -v

        ```

- `-t <threads>`: Specify the number of threads to use (default is 10). Higher values can speed up the enumeration.

    - Example:

        ```

        ./sublist3r.py -d acmeitsupport.thm -t 20

        ```

- `-e <engines>`: Choose specific search engines to use.

    - Example:

        ```

        ./sublist3r.py -d acmeitsupport.thm -e Google,Yahoo,Bing

        ```

- `-o <filename>`: Output results to a file for later reference.

    - Example:

        ```

        ./sublist3r.py -d acmeitsupport.thm -o results.txt

        ```

  
**Conclusion:** Running `./sublist3r.py -d acmeitsupport.thm` is a straightforward and effective way to kick start subdomain discovery.
