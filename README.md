**![](https://lh7-us.googleusercontent.com/cOsH7-Dh0nQaTbUkWHKOMA2-vu9L7rX8ZokdfVdqxbYmX32MuwiBf8chC6R8LLuexmKBgJL9dIIm0g2yEf1d_dA5VV8qGGL0vvzYf_rwDD7M0UdiHiZ35xVu9vJwsRWjSy3-DLQGXtR1YCMdn3ORDQ)**

<h1 align="center"> AI-powered Application to Safeguard Bhuvan Portal </h1>

<img src="assets/demo.gif?raw=true" width=100% alt="gif">

<div align="center">
Detects, Reports and Protects Bhuvan from Threats.
</div>

  <p align="center">
  <br/>
    <a href="https://mohakash.streamlit.app"> Streamlit App</a>
    ·
  <a href="https://app.powerbi.com/reportEmbed?reportId=14ca9c92-f434-4cbc-98cd-d43e683a7e94&autoAuth=true&ctid=23a21599-83e3-45ed-9e32-d7441e300908">Dashboard</a>
    ·
    <a href="https://github.com/asengupta07/Mohakash">Github</a>
  </p>


## What is BhuvanRKSHA?
BhuvanRKSHA is an application that helps keep the Bhuvan website safe by monitoring the logs and detecting suspicious behavior. We have implemented a bi-layer approach. 
- Primary model: Threat logs vs Clean logs 
- Secondary model: Classifies threat  into priority level 1, 2 and 3. 

Our Primary Model distinguishes clean logs from suspicious logs with **94.8%** accuracy. It is important to note that zero suspicious logs are misclassified as clean. All of the errors are clean logs misclassified as threats  which is where the model behaves extra cautious to not let any suspicious log pass undetected.

<p align="center"><img src="https://github.com/asengupta07/Mohakash/assets/136733971/8695a9a5-6d92-4c75-82cc-3a91fd458fec"></p>

All the predicted threats are passed into our Secondary Model and are then classified into priority levels 1 (mild suspicion), 2 (warning) and 3 (attack) which we have defined based on distinguishable differences between anomalous features. Our model classifies the threat levels with 99+% accuracy as there are noticeable differences between each level. 
We have planned to deal with each threat level differently.

- Level 3: IP addresses of threats are flagged and a notification is sent  to Bhuvan security team.
- Level 2: Bhuvan Security team is notified about the threat.
- Level 1: All the detected threats (along with level 2 and level 3) over a certain period of time (weekly/biweekly/monthly) are sent to the security team of Bhuvan to inspect.

## What We Have Done Till Now

<img align="right" src="https://github.com/asengupta07/Mohakash/assets/136733971/7de09503-4769-4910-a2b0-208575becb21" width="450px">

- Carried out exploratory data analysis and feature engineering on the raw data to figure out features that can be utilised to detect threats in the given logs.
- Minimised the number of features required to detect threats to best optimise the model using correlation analysis.
- Created a pipeline to convert the textual logs to clean trainable data with necessary important features.
- Trained a binary classification model to classify threats from clean logs with almost 95% accuracy. An Isolation forest model was used for this anomaly detection task.
- Trained the secondary multi-class classification model to classify priority of threats in three levels with almost cent percent accuracy. The model is a voting classifier ensembled with random forest, xboost and lightbgm.
- Created visual dashboards and reports on the data to give important insights.
- Analysed the server log dataset to visualise server traffic and traffic patterns in the interactive dashboard.
- Deployed the model that accepts multiple log data as either textual input or a file (upto 200 MB) corresponding to actual Bhuvan website's firewall log data file, preprocesses it and runs the predictions for all the logs at once. An interactive dashboard is also dynamically generated for better visualisation of the data.

<p align="center"><img src="https://github.com/asengupta07/Mohakash/assets/136733971/ae4cd3f9-3536-4e9c-be51-0801ccd8b1b3" width="400px"><img src="https://github.com/asengupta07/Mohakash/assets/136733971/cdf510a9-3938-49cc-ac99-e3086bd47ab6" width="400px"></p>


## What We Plan To Do Next

- Take dynamic data from Bhuvan and implement the pipeline into production.
- Add a real-time notification system based on threat level after running the dynamic firewall logs collected from Bhuvan's server logfile through the pipeline.
- Make the dashboards dynamic with the live data to give interactive daily, weekly, and monthly insights.
- Monitor the performance of our models and retrain to improve it with more data to get more robust models.

## The Team

- Aishi Mukhopadhyay
- Arnab Sengupta
- Akash Kundu
- Pradyumna Bhowmick

## Share Your Thoughts!

If you would like to share a feedback on the project, we would love to hear what you have to say. You can let us know how you feel through this [form](https://docs.google.com/forms/d/e/1FAIpQLScSe96ibyrVIUTZ3_8rIVUeGGQ9MWPAoD7wSBMyvQPbjM8kkg/viewform?usp=sharing).


**P.S:** We have added a demo gif in our readme, which unfortunately does not render on some devices. If you cannot see the demo of BhuvanRKSHA here, please open this [link](https://media.discordapp.net/attachments/1170293654896787498/1188532198735880293/demo.gif?ex=659addde&is=658868de&hm=549c62d3b7b8fd381fed4d6c72599ea4677f7ca9ea9aa5ec739a22302ed58733&=&width=1150&height=510), to view the 15 second demo. To test the deployed project yourself, check out our [streamlit app](https://bhuvanrksha.streamlit.app).
