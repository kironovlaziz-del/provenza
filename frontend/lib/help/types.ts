// The in-app help (app/(app)/help): articles for the people who use Provenza -
// guides by role, one article per feature, and the FAQ. Written for users, not
// developers: what a feature is for, when to use it, the steps, what to watch.
//
// An article is a list of blocks. Text may hold **bold** and [links](/path).

export type Block =
  | ["h", string]            // a heading inside the article
  | ["p", string]            // a paragraph
  | ["steps", string[]]      // numbered steps
  | ["list", string[]]       // bullet points
  | ["tip", string]          // a good practice
  | ["warn", string]         // something that cannot be undone, or a common mistake
  | ["qa", string, string];  // a question and its answer (FAQ)

export type HelpGroup = "start" | "roles" | "features" | "faq";

export interface Article {
  slug: string;
  group: HelpGroup;
  title: string;
  summary: string;
  /** Who it is mostly for: shown as tags on the help page. */
  roles?: ("admin" | "approver" | "auditor" | "compliance" | "user")[];
  /** The console page it explains: the article links to it. */
  page?: string;
  body: Block[];
}
