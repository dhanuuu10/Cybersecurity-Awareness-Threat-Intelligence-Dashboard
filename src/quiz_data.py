# =========================================================
# Cybersecurity Awareness Quiz Data
# =========================================================


QUIZ_QUESTIONS = [

    {
        "id": 1,
        "question": (
            "You receive an unexpected email asking you to "
            "verify your password through a link. What should "
            "you do first?"
        ),

        "options": [
            "Click the link immediately",
            "Reply with your password",
            "Verify the request through a trusted channel",
            "Forward the email to everyone"
        ],

        "correct_answer": (
            "Verify the request through a trusted channel"
        ),

        "explanation": (
            "Unexpected password requests may indicate phishing. "
            "The request should be independently verified before "
            "taking any action."
        ),

        "topic": "PHISHING"
    },


    {
        "id": 2,
        "question": (
            "Which practice provides stronger protection "
            "for an online account?"
        ),

        "options": [
            "Using the same password everywhere",
            "Sharing your password with a colleague",
            "Using multi-factor authentication",
            "Writing your password on a public notice"
        ],

        "correct_answer": (
            "Using multi-factor authentication"
        ),

        "explanation": (
            "Multi-factor authentication provides an additional "
            "security layer beyond the password."
        ),

        "topic": "ACCOUNT SECURITY"
    },


    {
        "id": 3,
        "question": (
            "What is a good practice when receiving an "
            "unexpected email attachment?"
        ),

        "options": [
            "Open it immediately",
            "Verify the sender and context first",
            "Forward it to friends",
            "Disable security software"
        ],

        "correct_answer": (
            "Verify the sender and context first"
        ),

        "explanation": (
            "Unexpected attachments can present security risks. "
            "The sender and context should be verified before "
            "opening an attachment."
        ),

        "topic": "MALWARE"
    },


    {
        "id": 4,
        "question": (
            "Which action is most useful for recovering from "
            "a ransomware incident?"
        ),

        "options": [
            "Keeping reliable backups",
            "Disabling all security controls",
            "Sharing passwords",
            "Ignoring system warnings"
        ],

        "correct_answer": (
            "Keeping reliable backups"
        ),

        "explanation": (
            "Reliable protected backups can help organizations "
            "recover data after a ransomware incident."
        ),

        "topic": "RANSOMWARE"
    },


    {
        "id": 5,
        "question": (
            "An unknown person urgently asks you to bypass "
            "normal security procedures. What should you do?"
        ),

        "options": [
            "Follow the request immediately",
            "Share confidential information",
            "Verify the person's identity and follow procedures",
            "Ignore all organizational policies"
        ],

        "correct_answer": (
            "Verify the person's identity and follow procedures"
        ),

        "explanation": (
            "Pressure to bypass security procedures is a common "
            "social-engineering warning sign."
        ),

        "topic": "SOCIAL ENGINEERING"
    },


    {
        "id": 6,
        "question": (
            "What should you do if a browser displays a "
            "security warning for a website?"
        ),

        "options": [
            "Ignore the warning",
            "Continue without checking",
            "Follow safe browsing procedures and verify the site",
            "Enter confidential information"
        ],

        "correct_answer": (
            "Follow safe browsing procedures and verify the site"
        ),

        "explanation": (
            "Browser security warnings should not be ignored. "
            "The website should be verified before continuing."
        ),

        "topic": "WEB SECURITY"
    },


    {
        "id": 7,
        "question": (
            "Which is the best practice for protecting "
            "sensitive information?"
        ),

        "options": [
            "Share it with everyone",
            "Store it anywhere without protection",
            "Limit access to authorized users",
            "Post it publicly"
        ],

        "correct_answer": (
            "Limit access to authorized users"
        ),

        "explanation": (
            "Sensitive information should only be accessible "
            "to authorized users who need it."
        ),

        "topic": "DATA PROTECTION"
    },


    {
        "id": 8,
        "question": (
            "You receive an unexpected authentication code "
            "on your phone. What should you do?"
        ),

        "options": [
            "Share the code with someone who asks",
            "Ignore the event and share the code later",
            "Do not share the code and investigate the activity",
            "Post the code online"
        ],

        "correct_answer": (
            "Do not share the code and investigate the activity"
        ),

        "explanation": (
            "Unexpected authentication codes may indicate an "
            "attempt to access your account. Authentication "
            "codes should never be shared."
        ),

        "topic": "ACCOUNT SECURITY"
    },


    {
        "id": 9,
        "question": (
            "What is one important reason to keep software "
            "and operating systems updated?"
        ),

        "options": [
            "To remove all passwords",
            "To improve security and address known weaknesses",
            "To disable security controls",
            "To make accounts public"
        ],

        "correct_answer": (
            "To improve security and address known weaknesses"
        ),

        "explanation": (
            "Security updates can address known vulnerabilities "
            "and improve the security of software."
        ),

        "topic": "MALWARE"
    },


    {
        "id": 10,
        "question": (
            "What should you do when you notice suspicious "
            "security activity on an organizational system?"
        ),

        "options": [
            "Hide the activity",
            "Delete all evidence",
            "Report it according to security procedures",
            "Share the details publicly"
        ],

        "correct_answer": (
            "Report it according to security procedures"
        ),

        "explanation": (
            "Prompt reporting allows the appropriate security "
            "team to investigate and respond according to "
            "organizational procedures."
        ),

        "topic": "INCIDENT AWARENESS"
    }
]


def get_quiz_questions():
    """
    Return all cybersecurity awareness quiz questions.
    """

    return QUIZ_QUESTIONS


def calculate_quiz_score(answers):
    """
    Calculate the quiz score.

    answers should be a dictionary where:
    key   = question ID
    value = selected answer
    """

    score = 0

    total_questions = len(
        QUIZ_QUESTIONS
    )


    results = []


    for question in QUIZ_QUESTIONS:

        question_id = question["id"]

        selected_answer = answers.get(
            question_id,
            ""
        )

        correct_answer = question[
            "correct_answer"
        ]


        is_correct = (
            selected_answer
            == correct_answer
        )


        if is_correct:

            score += 1


        results.append(
            {
                "question_id": question_id,
                "selected_answer": selected_answer,
                "correct_answer": correct_answer,
                "is_correct": is_correct,
                "explanation": question["explanation"],
                "topic": question["topic"]
            }
        )


    percentage = (
        score / total_questions
    ) * 100


    if percentage >= 90:

        awareness_level = "Excellent"

    elif percentage >= 75:

        awareness_level = "Good"

    elif percentage >= 50:

        awareness_level = "Developing"

    else:

        awareness_level = "Needs Improvement"


    return {
        "score": score,
        "total": total_questions,
        "percentage": percentage,
        "awareness_level": awareness_level,
        "results": results
    }