// script.js

// Define the questions for each assessment
const assessments = {
  BDI: [
    { question: "I feel sad.", options: ["Never", "Rarely", "Sometimes", "Often", "Always"] },
    { question: "I feel pessimistic about the future.", options: ["Never", "Rarely", "Sometimes", "Often", "Always"] }
  ],
  HDRS: [
    { question: "Do you feel depressed?", options: ["Not at all", "Somewhat", "Moderately", "Very much"] },
    { question: "Have you experienced sleep disturbances?", options: ["No", "Mild", "Moderate", "Severe"] }
  ],
  PHQ9: [
    { question: "Little interest or pleasure in doing things.", options: ["Not at all", "Several days", "More than half the days", "Nearly every day"] },
    { question: "Feeling down, depressed, or hopeless.", options: ["Not at all", "Several days", "More than half the days", "Nearly every day"] }
  ]
};

let currentAssessmentIndex = 0;
let currentQuestionIndex = 0;
let answers = [];

// DOM Elements
const assessmentContainer = document.getElementById("assessment-container");
const prevBtn = document.getElementById("prev-btn");
const nextBtn = document.getElementById("next-btn");
const submitBtn = document.getElementById("submit-btn");
const resultsDiv = document.getElementById("results");
const resultText = document.getElementById("result-text");
const closeBtn = document.getElementById("close-btn");

// Load the first question
function loadQuestion() {
  const assessmentKeys = Object.keys(assessments);
  const currentAssessmentKey = assessmentKeys[currentAssessmentIndex];
  const currentQuestions = assessments[currentAssessmentKey];

  // Clear the container
  assessmentContainer.innerHTML = "";

  // Add the title
  const title = document.createElement("h2");
  title.textContent = `${currentAssessmentKey}`;
  assessmentContainer.appendChild(title);

  // Add the question
  const question = document.createElement("p");
  question.textContent = currentQuestions[currentQuestionIndex].question;
  assessmentContainer.appendChild(question);

  // Add the options
  currentQuestions[currentQuestionIndex].options.forEach((option, index) => {
    const label = document.createElement("label");
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "answer";
    radio.value = option;
    radio.addEventListener("change", () => saveAnswer(option));
    label.appendChild(radio);
    label.appendChild(document.createTextNode(` ${option}`));
    assessmentContainer.appendChild(label);
    assessmentContainer.appendChild(document.createElement("br"));
  });

  // Update navigation buttons
  updateNavigation();
}

// Save the selected answer
function saveAnswer(answer) {
  answers[currentAssessmentIndex] = answers[currentAssessmentIndex] || [];
  answers[currentAssessmentIndex][currentQuestionIndex] = answer;
}

// Update navigation buttons
function updateNavigation() {
  const assessmentKeys = Object.keys(assessments);
  const currentAssessmentKey = assessmentKeys[currentAssessmentIndex];
  const currentQuestions = assessments[currentAssessmentKey];

  prevBtn.disabled = currentQuestionIndex === 0 && currentAssessmentIndex === 0;
  nextBtn.textContent = currentQuestionIndex < currentQuestions.length - 1 ? "Next" : "Next Assessment";
  nextBtn.disabled = !answers[currentAssessmentIndex]?.[currentQuestionIndex];
  submitBtn.style.display = currentAssessmentIndex === assessmentKeys.length - 1 && currentQuestionIndex === assessments[currentAssessmentKey].length - 1 ? "inline-block" : "none";
}

// Handle previous button click
prevBtn.addEventListener("click", () => {
  if (currentQuestionIndex > 0) {
    currentQuestionIndex--;
  } else if (currentAssessmentIndex > 0) {
    currentAssessmentIndex--;
    currentQuestionIndex = assessments[Object.keys(assessments)[currentAssessmentIndex]].length - 1;
  }
  loadQuestion();
});

// Handle next button click
nextBtn.addEventListener("click", () => {
  const assessmentKeys = Object.keys(assessments);
  const currentAssessmentKey = assessmentKeys[currentAssessmentIndex];
  const currentQuestions = assessments[currentAssessmentKey];

  if (currentQuestionIndex < currentQuestions.length - 1) {
    currentQuestionIndex++;
  } else if (currentAssessmentIndex < assessmentKeys.length - 1) {
    currentAssessmentIndex++;
    currentQuestionIndex = 0;
  }
  loadQuestion();
});

// Handle submit button click
submitBtn.addEventListener("click", () => {
  let result = "Assessment Completed!\n\n";
  Object.keys(assessments).forEach((key, index) => {
    result += `${key} Results:\n`;
    assessments[key].forEach((question, qIndex) => {
      result += `- ${question.question}: ${answers[index]?.[qIndex] || "No answer"}\n`;
    });
    result += "\n";
  });
  resultText.textContent = result;
  resultsDiv.style.display = "block";
});

// Handle close button click
closeBtn.addEventListener("click", () => {
  resultsDiv.style.display = "none";
});

// Initialize the app
loadQuestion();