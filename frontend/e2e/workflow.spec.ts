import {test,expect} from '@playwright/test';
test('human approval and independent verification complete the zero-day workflow',async({page})=>{
 async function login(user:string){await page.goto('/');await page.getByLabel('Principal').selectOption(user);await page.getByLabel('Password',{exact:true}).fill('local-demo-'+user);await page.getByRole('button',{name:'Open workspace'}).click();await expect(page.getByRole('heading',{name:'Overview',exact:true})).toBeVisible();}
 async function logout(){await page.getByRole('button',{name:/Sign out/}).click();await expect(page.getByLabel('Principal')).toBeVisible();}
 async function workbench(){await page.getByRole('button',{name:'06Zero-day response'}).click();}
 await login('analyst');
 await page.getByRole('button',{name:'Run investigation'}).click();
 await expect(page.getByText('Operation completed. Evidence and timeline updated.')).toBeVisible();
 await page.screenshot({path:'../docs/screenshots/overview.png',fullPage:true});
 await workbench();
 await page.getByRole('button',{name:'Propose isolation',exact:true}).click();
 await expect(page.getByText('Awaiting independent approval')).toBeVisible();
 await logout();await login('approver');await workbench();
 await page.getByRole('button',{name:'Approve exact action'}).click();
 await expect(page.getByText('Approved by approver')).toBeVisible();
 await logout();await login('analyst');await workbench();
 await page.getByRole('button',{name:'Execute simulation'}).click();
 await expect(page.getByRole('heading',{name:'verification pending',exact:true})).toBeVisible();
 await logout();await login('verifier');await workbench();
 await page.getByRole('button',{name:'Independently verify'}).click();
 await expect(page.getByRole('heading',{name:'mitigated',exact:true})).toBeVisible();
 await logout();await login('analyst');await workbench();
 await page.getByRole('button',{name:'Reveal vendor update'}).click();
 await expect(page.getByText('Operation completed. Evidence and timeline updated.')).toBeVisible();
 await page.getByRole('button',{name:'Propose patch 1.5'}).click();
 await expect(page.getByText('Awaiting independent approval')).toBeVisible();
 await logout();await login('approver');await workbench();
 await page.getByRole('button',{name:'Approve exact action'}).click();
 await expect(page.getByText('Approved by approver')).toBeVisible();
 await logout();await login('analyst');await workbench();
 await page.getByRole('button',{name:'Execute simulation'}).click();
 await expect(page.getByRole('heading',{name:'verification pending',exact:true})).toBeVisible();
 await logout();await login('verifier');await workbench();
 await page.getByRole('button',{name:'Independently verify'}).click();
 await expect(page.getByRole('heading',{name:'verified closed',exact:true})).toBeVisible();
 await page.screenshot({path:'../docs/screenshots/verified-closure.png',fullPage:true});
});
