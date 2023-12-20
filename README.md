**![](https://lh7-us.googleusercontent.com/cOsH7-Dh0nQaTbUkWHKOMA2-vu9L7rX8ZokdfVdqxbYmX32MuwiBf8chC6R8LLuexmKBgJL9dIIm0g2yEf1d_dA5VV8qGGL0vvzYf_rwDD7M0UdiHiZ35xVu9vJwsRWjSy3-DLQGXtR1YCMdn3ORDQ)**

<h1 align="center"> AI-powered application to safeguard Bhuvan Portal </h1>

<div align="center">
Detects, Reports and Protects  Bhuvan from threats.
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

Our Primary Model distinguishes clean logs from suspicious logs with **92%** accuracy. It is important to note that zero suspicious logs are misclassified as clean. All of the errors are clean logs misclassified as threats  which is where the model behaves extra cautious to not let any suspicious log pass undetected.
All the predicted threats are passed into our Secondary Model and are then classified into priority levels 1 (mild suspicion), 2 (warning) and 3 (attack) which we have defined based on distinguishable differences between anomalous features. Our model classifies the threat levels with 99+% accuracy as there are noticeable differences between each level. 
We have planned to deal with each threat level differently.

- Level 3: IP addresses of threats are flagged and a notification is sent  to Bhuvan security team.
- Level 2: Bhuvan Security team is notified about the threat.
- Level 1: All the detected threats (along with level 2 and level 3) over a certain period of time (weekly/biweekly/monthly) are sent to the security team of Bhuvan to inspect.

## What we have done till now

- Created a pipeline to convert the textual logs to clean trainable data with necessary important features.
- Trained a binary classification model to classify threats from clean logs with 92% accuracy. An Isolation forest model was used for this anomaly detection task.
- Trained the secondary multi-class classification model to classify priority of threats in three levels with almost cent percent accuracy. The model is a voting classifier ensembled with random forest, xboost and lightbgm.
- Created visual dashboards and reports on the data to give important insights.
- Analysed the server log dataset to visualise server traffic and traffic patterns in the interactive dashboard.
- Deployed the model that accepts data of multiple logs in given textual format, preprocesses it and runs the predictions for all the logs at once.

## What we plan to do next

- Take dynamic data from Bhuvan and implement the pipeline into production.
- Add a real-time notification system based on threat level after running the dynamic firewall logs collected from Bhuvan's server logfile through the pipeline.
- Make the dashboards dynamic with the live data to give interactive daily, weekly, and monthly insights.
- Monitor the performance of our models and retrain to improve it with more data to get more robust models.

## The team

- Aishi Mukhopadhyay
- Arnab Sengupta
- Akash Kundu
- Pradyumna Bhowmick

