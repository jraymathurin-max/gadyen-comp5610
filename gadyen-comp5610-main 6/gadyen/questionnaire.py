"""Onboarding questionnaire. Each question maps to one or more scoring controls.
User-facing translations live in the frontend (locales/en|es|fr|ht)."""

YES_NO_UNSURE = ["yes", "no", "unsure"]

QUESTIONS = [
    {"id": "Q01", "text": "What is the name of your practice?", "type": "text"},
    {"id": "Q02", "text": "How many people (including you and seasonal staff) use computers "
                          "for the practice?", "type": "number"},
    {"id": "Q03", "text": "About how many clients' records do you keep (all years)?",
     "type": "choice", "options": ["under_5000", "5000_or_more"]},
    {"id": "Q04", "text": "Who is responsible for information security in your practice? "
                          "(name and role; leave empty if nobody)", "type": "text",
     "controls": ["ORG-1"]},
    {"id": "Q05", "text": "Which email service does the practice use?",
     "type": "choice", "options": ["google_workspace", "microsoft_365", "gmail_or_outlook_personal",
                                    "other"]},
    {"id": "Q06", "text": "Is multi-factor authentication (a code or app in addition to the "
                          "password) turned on for EVERY email account?",
     "type": "choice", "options": YES_NO_UNSURE, "controls": ["ACC-1"]},
    {"id": "Q07", "text": "Is multi-factor authentication turned on in your tax software and "
                          "any client portal?", "type": "choice", "options": YES_NO_UNSURE,
     "controls": ["ACC-2"]},
    {"id": "Q08", "text": "Where is client information kept? (select all)", "type": "multi",
     "options": ["office_computers", "laptops", "cloud_storage", "tax_software_cloud",
                 "usb_drives", "paper"], "controls": ["DATA-1"]},
    {"id": "Q09", "text": "Do you back up client data, and have you tested restoring it?",
     "type": "choice", "options": ["yes_tested", "yes_not_tested", "no"],
     "controls": ["ORG-2"]},
    {"id": "Q10", "text": "Do visitors use a guest Wi-Fi network separate from the office "
                          "network?", "type": "choice", "options": ["yes", "no", "no_wifi"],
     "controls": ["NET-2"]},
    {"id": "Q11", "text": "How do you or your staff access office computers from outside?",
     "type": "choice", "options": ["no_remote_access", "vpn", "remote_support_tool",
                                    "remote_desktop_rdp"], "controls": ["NET-3"]},
    {"id": "Q12", "text": "Did everyone with access to client data receive security training "
                          "in the last 12 months?", "type": "choice", "options": YES_NO_UNSURE,
     "controls": ["ORG-3"]},
    {"id": "Q13", "text": "Do you have a written plan for what to do if client data is stolen "
                          "or a computer is hacked?", "type": "choice", "options": YES_NO_UNSURE,
     "controls": ["ORG-4"]},
    {"id": "Q14", "text": "Do you keep a list of the companies that handle your client data "
                          "(software, cloud, IT help) and check their security?",
     "type": "choice", "options": YES_NO_UNSURE, "controls": ["ORG-5"]},
    {"id": "Q15", "text": "How do you destroy old paper files and old computers or drives?",
     "type": "choice", "options": ["shred_and_wipe", "shred_only", "trash", "not_sure"],
     "controls": ["ORG-6"]},
    {"id": "Q16", "text": "What is the domain of your website or email (for example "
                          "mytaxoffice.com)? Leave empty if you use a personal Gmail/Outlook "
                          "address.", "type": "text"},
]

QUESTION_IDS = {q["id"] for q in QUESTIONS}


def validate_answers(answers: dict) -> dict:
    clean = {}
    by_id = {q["id"]: q for q in QUESTIONS}
    for qid, value in answers.items():
        q = by_id.get(qid)
        if q is None:
            raise ValueError(f"unknown question {qid}")
        if q["type"] == "choice" and value not in q["options"]:
            raise ValueError(f"{qid}: invalid option {value!r}")
        if q["type"] == "multi" and not (isinstance(value, list)
                                         and all(v in q["options"] for v in value)):
            raise ValueError(f"{qid}: invalid options")
        if q["type"] == "number" and not (isinstance(value, int) and 0 <= value <= 10000):
            raise ValueError(f"{qid}: must be a whole number")
        if q["type"] == "text" and not (isinstance(value, str) and len(value) <= 200):
            raise ValueError(f"{qid}: text too long")
        clean[qid] = value
    return clean
