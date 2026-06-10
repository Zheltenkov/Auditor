# Integration with REST web-services 

Summary: In this project you will study the interaction of web-services between IT systems through the REST architectural style, the advantages and disadvantages of such communication, learn how to read and compose messages. You will also learn what is data mapping (received and sent) and how to describe errors.

💡 [Tap here](https://new.oprosso.net/p/4cb31ec3f47a4596bc758ea1861fb624) **to leave your feedback on the project**. It's anonymous and will help our team make your educational experience better. We recommend completing the survey immediately after the project.

## Contents

1. [Chapter I](#chapter-i) \
   1.1. [Preamble](#11)
2. [Chapter II](#chapter-ii) \
   2.1. [General Rules](#21)
3. [Chapter III](#chapter-iii) \
   3.1. [Theory](#31) \
   3.2. [General Concepts](#32) \
   3.3. [Documentation](#33) \
   3.4. [Mapping](#34) \
   3.5. [Error Handling](#35)
4. [Chapter IV](#chapter-iv) \
   4.1. [Task 1. Haircut Appointment](#41)
5. [Chapter V](#chapter-v) \
   5.1. [Exercise 00 – Terminology](#51) \
   5.2. [Exercise 01 — Data Preparation](#52) \
   5.3. [Exercise 02 — UC Update](#53) \
   5.4. [Exercise 03 — References Integration](#53) \
   5.5. [Exercise 04 — Definition and Description of Methods](#55) \
   5.6. [Exercise 05 — Description of Request/Response Elements](#56) \
   5.7. [Exercise 06 — Mapping](#57) \
   5.8. [Exercise 07 — Errors Description](#58) \
   5.9. [\*Exercise 08 — UC Update](#59) \
   5.10. [\*Exercise 09 — Definition and Description of Methods](#510)

## Instructions 

How to learn at “School 21”:

- Here, you’ll find a unique learning experience with a lot of freedom. You’re given a task and left to find your own way to solve it, using whatever resources work best for you — whether that’s the Internet or AI tools like GigaChat. Just be mindful of information quality: verify, think critically, analyze, and compare.
- Peer-to-peer (P2P) learning is the exchange of knowledge and experience with peers, where everyone acts as both mentor and student. This approach allows you to gain a deeper understanding of the material by learning from one another.
- Feel free to ask for help: around you are peers who are also navigating this path for the first time. Share your own experience and ideas with others.  Join Rocket.Chat to stay updated with the latest community announcements. 
- Your learning is meaningless if you just copy someone else’s solutions. When receiving help from others, always make sure you fully understand the “why”, “how”, and “purpose” behind the solution. Don’t be afraid to make mistakes. 
- Does the task seem impossible? Take a break, get some fresh air and clear your mind — this has helped many people. Maybe after that, the solution will come to you naturally.
- The learning process is just as important as the result. It’s not just about completing the task — it’s about understanding HOW to solve it.

## Chapter I <div id="chapter-i"></div>

![Illustration](misc/images/IMG_1815.jpg)

### Preamble <div id="11"></div>

REST is an architectural style, a set of rules for how systems or components interact to exchange data. REST is a consistent set of constraints that are considered when designing system interactions.

### Literature

1. [Н. Krikun "How to stop catching "fleas" in integration"](https://rutube.ru/video/389ea1d1c354dd752e532843c1985281/).
2. [Fear integration — don't go into analytics](https://habr.com/ru/companies/maxilect/articles/592533/).
3. [How an analyst should work with tasks on integration — step-by-step instructions / habr.com](https://habr.com/ru/articles/735332/).
4. [What is API](https://habr.com/ru/articles/464261/).
5. [D. Leonov "REST API: an approach to solving the integration problem"](https://rutube.ru/video/d6b6228b503e28041f50d11d2f9e26f5/).

## Chapter II <div id="chapter-ii"></div>

### General Rules <div id="21"></div>

Before starting, clone the project from GitLab into a repository with the same name.

1. Along the way, you may feel a sense of uncertainty and a severe lack of information: that's OK. Remember, the information in the repository and on Google is always with you. So are your peers and Rocket.Chat. Communicate. Search. Use common sense. Don't be afraid to make mistakes.
2. Pay attention to sources of information. Check. Think. Analyse. Compare. 
3. Look at the text of each assignment. Read it several times. 
4. Read the examples carefully. There may be something in them that is not explicitly stated in the task itself.
5. You may find inconsistencies where something new in the terms of the task or examples conflicts with something you already know. If you come across such an inconsistency, try to work it out. If not, write it down as an open question and find out as you work. Do not leave open questions unanswered. 
6. If a task seems confusing or impossible, it only seems that way. Try to break it down. It is likely that some parts will become clear. 
7. There will be several tasks. Those marked with an asterisk (\*) are for the more meticulous students. These tasks are more difficult and are not compulsory. But doing them will give you extra experience and knowledge.
8. Don't try to fool the system or the people around you. You will fool yourself first.
9. Got a question? Ask your neighbour to the right. If that doesn't help, ask your neighbour on the left.
10. When you use help, you should always understand why and how. Otherwise the help is useless.
11. Always push only to the _develop_ branch! The master branch will be ignored. Work in the _src_ directory.
12. There should be no files in your directory other than those specified in the tasks.

## Chapter III <div id="chapter-iii"></div>

### 1. Theory <div id="31"></div>

REST (Representational State Transfer, [Roy Fielding](https://en.wikipedia.org/wiki/Roy_Fielding) 2000г.) is an architectural style for providing standards for communication between computer systems in a network. Following the standards makes it easier for systems to communicate with each other. Systems that are REST-compliant and are often referred to as RESTful. 

A RESTful integration architecture should follow the 6 principles (Fielding's Constraints):

1. Client-server architecture: separation of responsibilities; client and server functions are separated. 
2. Statelessness: the server receives all the information to process in each request (does not store the information in itself).
3. Cacheability: the server stores responses for future use.
4. Uniform interface (HATEOAS): style constraints by which the server returns not only the resource, but also its relationships to other resources and the actions that can be performed on it.
5. Layered system: neither the client nor the server is aware of the call chain beyond their direct contacts.
6. Code on demand: transfer of executable code (optional).

You can learn more about the principles and characteristics of the REST architectural style, advantages and disadvantages of the approach in the article by A. Burakov "REST, what are you? A clear introduction to the technology for IT analysts".

### 2. General Concepts <div id="31"></div>

**Data Presentation Format**: The way the data is transferred, such as:

- XML — information markup language;
- JSON — text format for exchanging data;
- Binary — binary format.

**Data Transfer Protocol:** A set of agreements that define how data is exchanged between systems and/or components of systems. The agreements specify:

- exchange rules;
- a set of data transfer formats;
- a uniform method of message transmission;
- error handling procedures.

**Transport:** Network transmission protocols.

**Resources: https://21-school.ru/blog**.

**https://** — sheme, transport indication, protocol.

**21-school.ru** — host, the server to communicate with. 

**blog** — resource, the object with which interaction is performed, School 21 blog.

**HTTP is a widely used data transfer protocol that was originally designed to transfer hypertext documents (i.e., documents that may contain links that allow you to navigate to other documents). It is also used to transfer arbitrary data.

**HTTP Methods**

The integration operations in RESTful are described by HTTP verbs.

There are 4 main HTTP methods that are used in requests to interact with resources in the REST system:

GET — retrieve a specific resource (by ID) or a collection of resources;

POST — create a new resource;

PUT — update a specific resource (by ID);

DELETE — delete a specific resource by ID.

**API** is:

- Application Programming Interface, a description of the way software systems or components of systems interact.
- A mechanism for interaction between program components.
- A product that allows external users to provide access to a system.

API is a contract (agreement, description) of interaction between programs. It contains:

- The operation that the system should (and can) perform;
- Input data (data received as input);
- Output data (data that can be obtained as a result of the operation);
- error messages (description of errors).  

Some articles on integration and APIs:

1. [Molechka](https://habr.com/ru/users/Molechka/) "What is API" <https://habr.com/ru/articles/464261/#directly>.
2. [katherine_a](https://habr.com/ru/users/katherine_a/) "How an analyst should work with tasks on integration — step-by-step instructions" https://habr.com/ru/articles/735332/.

### 3. Documentation <div id="33"></div>

The documentation includes:

1) syntax of request and response (what is passed, how it is passed);
2) examples of request and response;
3) description of input and output parameters (what we pass in request and response).

Example documentation: <https://yandex.ru/dev/rasp/doc/reference/schedule-point-point.html>

### 4. Mapping <div id="34"></div>

One of the most important parts of an integration analyst's job is mapping data from different sides of the integration. Data in systems that communicate with each other and in data that is transferred may be stored in different structures. For example, in one system the full name is a single required field, in another system it is three fields and only two of them are required and the patronymic may not be filled in, and in a third system all three fields are required. Or when specifying monetary amounts: when transferring (reading/writing) monetary data in numeric format, rounding distortions may occur. 

Mapping is the assignment of data fields in different data storage and transmission sources. Consider whether data mapping is required for almost any type of exchange. 

What to compare and consider when mapping

1. Identifier — the system name of the field under which the data is stored in the source or transmitted in the message. If the field is stored in a table — a record with a period (table identifier, field identifier). Or the name of the table is written above, as a table of contents of the field group.
2. Business name / description of the field.
3. Data type (text, number (integer or fractional), date, list of values, etc.). 
4. Dimensionality (length of the field).
5. Mandatory; may be different for sending and receiving systems.
6. Comments: conditions, restrictions, processing/transformation order, if necessary.

### 5. Errors Handling <div id="35"></div>

The receiving system accepts messages generated by another system. It is not always the case that the sending system generates the message as agreed in the contract. Therefore, when receiving a message, the receiving system should check the message it receives. And if incorrect messages are received, the sending system should be notified of the problem. The system can send such messages in the response (in the error message field). The description of received inconsistencies is usually prepared by the analyst, as he/she knows well what should be checked in the received message. Format requirements (data type, dimensionality, mandatory), presence in the reference (if it is a link to a record in the reference), other logical conditions are checked. 

In addition, error messages contain other information, such as the inaccessibility of the receiving system. 

## Chapter IV <div id="chapter-iv"></div>

### Description of tasks

### Task 1. Haircut Appointment<div id="41"></div>

The management of a chain of barbershops decided to implement an online booking system. The main objective is to develop the business by expanding the customer base through the possibility of online registration, as well as to reduce employee labour costs and manual labour by automatically informing customers through communication channels. 

Both registered and unregistered visitors can book an appointment on the website. When making an appointment, they can select the type of service: hairdressing or cosmetology, as well as the service itself, the master and the time from the available intervals. The system should provide automatic sending of reminders to clients through the communication channel chosen by the client (Telegram, WhatsApp, VK, SMS) according to the schedule set by the manager. After receiving a service, the system offers the client to evaluate the service and write suggestions on how to improve the work.

The schedule of masters and the services provided by each master should be entered by the manager, who may be more than one person. This person is also responsible for keeping the schedule up to date and adjusting it if necessary, communicating with customers manually, marking the service, charging and accepting payment, sending the payment data to the accounting department. The manager can also receive reports on completed services and view customer feedback.

Each master has the ability to view the schedule and appointments for their services, as well as customer reviews.

**Terms**

**Slot**: 1 hour time period, initial time is indicated.

**UC01 Register a client (self-registration)**

**Use context:** Client registers to sign up for service.

**Scope:** Barbershop, providing services.

**Level:** User goal.

**Main Actor:** Client.

**Preconditions:** The client has entered the website.

**Main scenario:**

1. The client opens the registration page.
2. The client enters their phone number and name (patronymic).
3. The system confirms that the phone is not registered in the system.
4. The client enters the preferred password.
5. The system informs the password level (weak, medium, high).
6. The system registers the client, sends SMS to the client about registration with name and login.

**Alternative scenario:**

1. The entered phone number is registered in the system:
   1. The system reports that such a phone number is registered in the system.
   2. The client enters another phone number (2.) or refuses to register.

**UC04 Register Client (Manager)**

**Use context:** A manager, when communicating with a client over the phone, registers the client to book a service.

**Scope:** barbershop, providing services to clients.

**Level:** User goal.

**Main actor:** Manager.

**Preconditions:** A client called the manager. The manager accessed the barbershop's website.

**Main scenario:**

1. The manager opens the client registration page.
2. The manager enters their phone number and name that the client provided over the phone.
3. The system confirms that the phone is not registered in the system.
4. The system registers the client, generates a temporary password, sends a SMS to the client's phone about registration with name, login, temporary password.

**Alternative scenario:**

1. The entered phone is registered in the system:
   1. The system informs that such phone number is registered in the system.
   2. Client enters another phone number (2.) or refuses to register.

## Chapter V <div id="chapter-v"></div>

### Exercise 00 – Terminology <div id="51"></div>

1. Match terms (A-D) and their definitions/explanations. 
2. For each term, select one option from 1) — 8).

**Terms:**

1. REST;
2. Caching;
3. Scalability;
4. Asynchrony.

**Definitions and Explanations:**

1) Inconsistency, disagreement with something in time; non-simultaneity. 
2) Coordination of movements, actions of two or more people, events, or processes.
3) An architectural style for the interaction of distributed application components in a network.
4) A protocol proposed by Roy Fielding for the interaction of distributed application components.
5) The ability of a system, network, or process to increase its performance as resources are added.
6) The property of a method that allows the service to be returned to the same state as when it was first called.
7) The ability of a system, network, or process to increase its performance without adding resources.
8) Increasing the performance of Web applications by using previously stored data.
9) Information fatigue syndrome.

### Exercise 01 — Data Preparation <div id="52"></div>

Pick up and transfer from previous projects.

1. Find among your fellow students those who worked in a group other than your own when completing BSA09. 
2. From the BSA09 project, select the classes required to implement UC02, UC04. 
3. Transfer the data structures and attribute descriptions:
   1. from your project; 
   2. from another group's project.

### Exercise 02 — UC Update <div id="53"></div>

Analyze and if necessary, refine UC04 Register Client (Manager).

What to do:

1. Describe the complete sequence of steps and alternative scenarios for each step.
2. Specify information in each step of the scenario:
   1) about the application (server, client, service);
   2) the role(s) performing the actions.
3. For steps that involve integration interaction, specify the integration methods.
4. List the references used in UC.
5. In case links to references are involved in integration interaction, finalize UC taking into account the transfer of reference data (choose one of the options):
   1) the actual reference is transferred before the UC is executed (include in the precondition);
   2) the required reference record is transferred together with the initial message;
   3) the references are updated as needed if a missing record is detected.

### Exercise 03 — References Integration <div id="54"></div>

For the directories used in UC04 Register a Client (Manager), describe the integration solution:

1. Write out the references that are used in UC.
2. For each reference, indicate whether integration is required.
3. If integration is required, specify the integration option:
   1) full transfer;
   2) transfer of delta (changes since the previous transfer);
   3) transfer of records related to the transferred data;
   4) search for the reference record corresponding to the transferred data.
4. According to the selected solution option, add an integration method for each transferred reference.

### Exercise 04 — Definition and Description of Methods <div id="55"></div>

According to the conditions of Task 1, describe the requirements for integration UC04 Register a Client (Manager).

1. Generate question-answer sets for each integration case.
2. Determine which HTTP method is more appropriate for each integration case, including references, based on the following criteria: 
   1) What CRUD operation will be performed on the data?
   2) Is it necessary to use a secure method?
   3) Is it necessary to use an idempotent method?
3. Each query must include:
   1) The method;
   2) the assumed URL path;
   3) parameters (if applicable);
   4) request body — a description of what the body should contain (if applicable). 
4. The response set must contain at least 2 responses - successful and unsuccessful. 
5. All responses must include: 
   1) a status code;
   2) the body of the response — a description of what it should contain (if applicable).

### Exercise 05 — Description of Request/Response Elements <div id="56"></div>

For each integration option UC04 Register Client (Manager), describe the elements of the request/response body (input/output parameters).

Specify:

1. Option to integrate from UC, including references; 
2. Assign integration by business;
3. Method;
4. Direction of transfer;
5. Request or response;
6. List of request/response body elements with details:
   1) Block identifier (if necessary),
   2) Element identifier,
   3) Name by business,
   4) Element Type,
   5) Dimensionality (field length),
   6) Mandatory,
   7) Correspondence of the element to the sending system for requests or the receiving system for responses,
   8) Comments (restrictions, conditions, reference).

### Exercise 06 — Mapping <div id="57"></div>

For each integration option UC04 Register Client (Manager), perform request/response body data mapping (input/output parameters):

1) between the sending system and the transferred message; 
2) between the message to be transferred and the recipient system.

Specify:

1. System side: 
   1. entity/class (identifier and name by business),
   2. nested block/multiplicity,
   3. element/field,
   4. data type,
   5. dimensionality,
   6. mandatory,
   7. conditions, constraints,
   8. link to reference;
2. Message side — specified in ex.5.

### Exercise 07 — Errors Description <div id="58"></div>

For each integration option, UC04 Register a Client (Manager), describe the elements of the request/response body (input/output parameters), describe the requirements for handling errors that may occur during integration, specify:

1) integration option;
2) tested element;
3) test condition;
4) error code;
5) error message;
6) criticality (warning / criticism / blocker).

1. Describe the error handling requirements for each step. 
2. Consider the requirements when receiving external system messages:
   1. field mandatory violation;
   2. type violation;
   3. dimensionality violations;
   4. logical conditions;
   5. for processing of inaccessibility of the external system;
   6. requirements for matching links to records in references of different systems.
3. Describe at least 15 error handling requirements for each integration option.  

### \*Exercise 08 — UC Update <div id="59"></div>

Analyze and refine UC02 Create master schedule as needed.

Do the following:

1. Describe the complete sequence of steps and alternative scenarios for each step. 
2. Specify in each step scenario information:
   1. about the application (server, client, service);
   2. the role(s) that perform the actions.
3. For steps where there is integration interaction, specify integration methods.

### \*Exercise 09 — Definition and Description of Methods <div id="510"></div>

Using the conditions from Task 1, describe the queries for integrating UC02 Create Master Schedule.

1. Create question-answer sets for each integration case. 
2. Determine which HTTP method is more appropriate for each integration case based on the following criteria 
   1) What CRUD operation will be performed on the data?
   2) Is it necessary to use a secure method?
   3) Is it necessary to use an idempotent method?
3. Each request must contain:
   1) the method;
   2) the assumed URL path;
   3) parameters (if applicable);
   4) the body of the request or a description of what the body should contain (if applicable). 
4. The response set must contain at least 2 responses — successful and unsuccessful. 
5. All responses must contain: 
   1) a status code;
   2) the body of the response or a description of what it should contain (if applicable).
