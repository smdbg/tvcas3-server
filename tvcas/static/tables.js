/* Sorting is local to the displayed page; no requests or background polling. */
for (const table of document.querySelectorAll('table')) {
  const head = table.tHead;
  if (!head || !table.tBodies.length) continue;
  const headers = Array.from(head.rows[0].cells);
  headers.forEach((cell, column) => {
    if (cell.textContent.trim() === 'Действия') return;
    const label = cell.textContent;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'sort';
    button.textContent = label + ' ↕';
    cell.textContent = '';
    cell.append(button);
    button.addEventListener('click', () => {
      const ascending = cell.getAttribute('aria-sort') !== 'ascending';
      headers.forEach(header => header.removeAttribute('aria-sort'));
      cell.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
      const rows = Array.from(table.tBodies[0].rows);
      if (rows.some(row => row.cells.length !== headers.length)) return;
      rows.sort((a,b) => {
        const left = a.cells[column].dataset.sortValue ?? a.cells[column].textContent.trim();
        const right = b.cells[column].dataset.sortValue ?? b.cells[column].textContent.trim();
        return (ascending ? 1 : -1) * left.localeCompare(right, 'bg', {numeric: true, sensitivity: 'base'});
      });
      rows.forEach(row => table.tBodies[0].append(row));
    });
  });
}
