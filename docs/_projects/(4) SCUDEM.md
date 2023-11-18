---
name: Punishing Infants
tools: [Math Modeling, Markov Chain, Matplotlib]
image: https://raw.githubusercontent.com/079035/079035.github.io/master/docs/_projects/scudem/model.png
description: Math Modeling Competition Submission for SCUDEM - SIMIODE Challenge Using Differential Equations Modeling
---

# Punishing Infants
### Problem Statement:
![alt text](https://raw.githubusercontent.com/079035/079035.github.io/master/docs/_projects/scudem/scudem-2-1.png)
### Summary of Problem:
- Study done on the tendency to punish antisocial behavior
- Researchers found that infants have the innate capacity to “punish” 
- Infants will punish those who they believe are hurting others
- Based on this we will assume that is a human trait
- What does this natural tendency imply about society?
- What does this say about the long-term dynamics of different populations?

### Goals of our Model
- Our model hopes to describe the effect punishment systems have towards reducing aggression within a population.
- We hope to see how changing the punishment system or the population would affect the equilibrium state of our population.
- Closed population - no births or deaths over the time span
- Three different states: Aggressors, Neutral, Incarcerated
- There is the ability to change from one state to another
- Punishment for the aggressors is incarceration

## Model
![alt text](https://raw.githubusercontent.com/079035/079035.github.io/master/docs/_projects/scudem/model.png)
- I = incarcerated
- A = aggressive
- N = not-aggressive (neutral)
- k1 is the proportion of people leaving jail with corrected behavior
- k2 is the proportion of neutral people who become aggressive
- t1 is the proportion of people who stay incarcerated

![alt text](https://raw.githubusercontent.com/079035/079035.github.io/master/docs/_projects/scudem/markov.png)

## Simulation
We implemented our simulation through Python in Jupyter, and using 100 iterations with the initial sample variables of:

I = 0
A = 100
N = 900
### Simulation Goals
- What would happen if people stayed in jail longer? 
- Or if jail better corrected behavior? 
- Or our population was more aggressive?
- Varying values for t1, k1, and k2 while everything else constant

[**Model Code**](https://colab.research.google.com/drive/1ciyPTq1ldpTh46roqtWqZkvdW2fFYayx?usp=sharing)

## Observations
![alt text](https://raw.githubusercontent.com/079035/079035.github.io/master/docs/_projects/scudem/results.png)

- Within our model, effective punishments are ideal
- This means that punishment that results in people changing and becoming less aggressive results in the highest neutral population
- Furthermore, we want to avoid excessive punishment as this ultimately hurts the population which results in the lowest neutral population

## Video Explanation
[**Youtube**](https://www.youtube.com/watch?v=BgyvjgL54UI)

Thank you.
