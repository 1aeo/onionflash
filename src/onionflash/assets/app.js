"use strict";

// Progressive enhancement: every story and source link works without JavaScript.
(() => {
  const year = String(new Date().getFullYear());
  document.querySelectorAll("[data-copyright-year]").forEach((node) => {
    node.textContent = year;
  });

  const tools = document.querySelector("[data-news-tools]");
  const search = document.getElementById("news-search");
  const list = document.getElementById("news-list");
  if (!tools || !search || !list) return;
  const stories = Array.from(list.querySelectorAll(".story"), (node) => ({
    node,
    topics: new Set((node.dataset.tags || "").split(" ")),
    text: node.dataset.search || "",
  }));
  if (!stories.length) return;
  const buttons = Array.from(tools.querySelectorAll("[data-filter]"));
  const count = document.getElementById("result-count");
  const empty = document.getElementById("no-results");
  let category = "all";
  let scheduled = false;

  const apply = () => {
    scheduled = false;
    const query = search.value.trim().toLocaleLowerCase();
    let visible = 0;
    for (const story of stories) {
      const matches = (category === "all" || story.topics.has(category))
        && (!query || story.text.includes(query));
      story.node.hidden = !matches;
      if (matches) visible += 1;
    }
    if (count) count.textContent = `${visible} ${visible === 1 ? "story" : "stories"}`;
    if (empty) empty.hidden = visible !== 0;
  };

  for (const button of buttons) {
    button.addEventListener("click", () => {
      category = button.dataset.filter || "all";
      for (const choice of buttons) {
        const active = choice === button;
        choice.setAttribute("aria-pressed", String(active));
        choice.classList.toggle("active", active);
      }
      apply();
    });
  }
  search.addEventListener("input", () => {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(apply);
  });
  tools.hidden = false;
})();
