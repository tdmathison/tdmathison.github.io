---
title: Scripts
icon: fas fa-code
order: 5
---

<style>
#scripts-table { width: 100%; border-collapse: collapse; }
#scripts-table th, #scripts-table td { padding: 0.4rem 0.6rem; border-bottom: 1px solid #ddd; }
#scripts-table th { text-align: left; }
details summary { cursor: pointer; color: #007acc; }
details[open] summary { color: #005f99; }
details { margin: 0; }
</style>

### Filter by Category
<div id="category-filters" style="margin-bottom:0.8rem">
  <button data-cat="all">All</button>
  {% assign cats = site.scripts | map: "categories" | uniq | flatten | sort %}
  {% for c in cats %}
    <button data-cat="{{ c }}">{{ c }}</button>
  {% endfor %}
</div>

<table id="scripts-table">
  <thead>
    <tr>
      <th style="width:35%">Title</th>
      <th style="width:45%">Categories</th>
      <th style="width:20%">Script</th>
    </tr>
  </thead>
  <tbody>
  {% for script in site.scripts %}
  <tr class="script-row" data-categories="{{ script.categories | join: ' ' }}">
    <td>{{ script.title }}</td>
    <td>{{ script.categories | join: ', ' }}</td>
    <td>
      <button class="toggle-code">View</button>
    </td>
  </tr>
  <tr class="code-row" style="display:none">
  <td colspan="3" class="code-cell">
    <div class="script-code">
      {{ script.content | markdownify }}
    </div>
  </td>
</tr>



  {% endfor %}
</tbody>

</table>

<script>
document.addEventListener("DOMContentLoaded", () => {
  const toggleButtons = document.querySelectorAll('.toggle-code');
  const scriptRows = document.querySelectorAll('#scripts-table tbody tr.script-row');
  const codeRows   = document.querySelectorAll('#scripts-table tbody tr.code-row');

  toggleButtons.forEach((btn, i) => {
    btn.addEventListener('click', () => {
      const codeRow = codeRows[i];
      const showing = codeRow.style.display !== 'none';
      codeRow.style.display = showing ? 'none' : '';
      btn.textContent = showing ? 'View' : 'Hide';
    });
  });

  const filterButtons = document.querySelectorAll('#category-filters button');
  filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const cat = btn.dataset.cat;
      scriptRows.forEach((row, i) => {
        const categories = row.dataset.categories;
        const match = cat === 'all' || categories.includes(cat);
        row.style.display = match ? '' : 'none';
        codeRows[i].style.display = 'none';
        toggleButtons[i].textContent = 'View';
      });
    });
  });
});
</script>

<style>
td.rouge-code {
  width: 100% !important;
}
.code-cell {
  padding: 0 !important;
  margin: 0 !important;
  background: transparent !important;
  border: none !important;
}

.script-code {
  width: 100%;
  margin: 0;
}

.script-code pre,
.script-code code {
  display: block;
  width: 100%;
  margin: 0;
  padding: 1rem;
  white-space: pre-wrap;
  word-break: break-word;
  background-color: #f9f9f9;
}
.highlight pre,
.highlight code {
  margin: 0 !important;
  padding: 0 !important;
  background: transparent !important;
  border: none !important;
}
.highlight {
  margin: 0 !important;
  padding: 0 !important;
  background: transparent !important;
}

.highlight table {
  border-spacing: 0 !important;
  border-collapse: collapse !important;
  margin: 0 !important;
  padding: 0 !important;
  width: 100% !important;
}

td.rouge-code,
td.rouge-gutter {
  margin: 0 !important;
  padding: 0 !important;
  background: transparent !important;
  border: none !important;
}
td.rouge-gutter {
  padding-right: 0.75rem !important;
  text-align: right;
  user-select: none;
  background: transparent;
}

td.rouge-code {
  padding-left: 0 !important;
}
</style>


<script>
document.addEventListener("DOMContentLoaded", () => {
  const buttons = document.querySelectorAll('#category-filters button');
  const rows    = document.querySelectorAll('#scripts-table tbody tr');

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const cat = btn.dataset.cat;
      rows.forEach(row => {
        const match = cat === 'all' || row.dataset.categories.includes(cat);
        row.style.display = match ? '' : 'none';
      });
    });
  });
});
</script>

