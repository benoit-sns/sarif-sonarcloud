# sarif-sonarcloud
Convert sonarcloud issues to sarif report

Add this configuration to your Github Action worlflow, after running the sonarcloud analysis:

```
    [...]
    steps:
    - name: Checkout repository
      uses: actions/checkout@v2

    - name: SonarCloud Scan # Use appropriate scanner if your project contains languages not compatible with sonar-scanner-cli ()Java/C#,C,C++ etc...)
      uses: sonarsource/sonarcloud-github-action@master
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}

    - name: Generate SonarCloud sarif report
      uses: benoit-sns/sarif-sonarcloud@master
      env:
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN}} # token to call the sonarcloud api
        REPORT_PATH: <path-to-report-path> # Path to the report-task.txt file generated when running the scanner. Optional unless you did not run the scanner in the workspace directory.
    - name: Upload sarif report
      uses: Anthophila/codeql-action/codeql/upload-sarif@master
      with:
        sarif_file: sonarcloud-output.sarif.json

```
