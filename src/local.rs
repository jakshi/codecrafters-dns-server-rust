use crate::dns_question_and_answer::{DnsAnswer, DnsQuestion};

/// Create response answers based on the questions
/// Takes a reference to questions, returns owned answer structures
/// This is a dummy implementation that returns 8.8.8.8 for all queries
pub fn create_response_answers(questions: &[DnsQuestion]) -> Vec<DnsAnswer> {
    questions
        .iter()
        .map(|question| {
            // For now, return a dummy A record pointing to 8.8.8.8
            DnsAnswer::new_a_record(
                question.name.clone(),
                60, // TTL: 60 seconds
                [8, 8, 8, 8],
            )
        })
        .collect()
}
